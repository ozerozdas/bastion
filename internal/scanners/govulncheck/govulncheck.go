// Package govulncheck implements bastion's opt-in Go reachability enrichment
// (#37, PROJECT_SPEC.md §1.6).
//
// Most vulnerable functions are never called. When the enrichment is on, a
// scan of a Go module runs govulncheck in source mode and marks each Go
// vulnerability finding `reachable` when govulncheck reports a call trace for
// that advisory, `unreachable` when it reports it only at package or module
// level, and `unknown` when there is no answer.
//
// govulncheck needs a Go toolchain on PATH and network access (module
// downloads, the vuln.go.dev database), so the enrichment is opt-in and off by
// default. Every failure degrades to `unknown`: it never fails a scan.
//
// The analysis runs in a child process: bastion re-execs itself with the
// hidden internal-govulncheck subcommand, which calls golang.org/x/vuln/scan
// in-process. x/vuln v1.9.0 does not plumb the context into its package
// loading, so an in-process run cannot be bounded; a child lets the parent
// enforce a deadline and kill the whole process group, and lets it hand the
// child a deliberately small environment instead of inheriting secrets.
package govulncheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
)

// Name is the stable scanner id stored in scanner_runs.
const Name = "govulncheck"

// InternalCommand is the hidden subcommand the enrichment re-execs bastion
// with. The child runs govulncheck and streams its JSON to stdout.
const InternalCommand = "internal-govulncheck"

// libraryVersion is the golang.org/x/vuln release this package is built
// against. Keep it in step with go.mod: scanner_runs records it so a scan's
// reachability can be traced to the analyzer that produced it.
const libraryVersion = "v1.9.0"

// DefaultTimeout bounds one scan's analysis across every module. The first run
// may download the vulnerability database, so it is generous.
const DefaultTimeout = 10 * time.Minute

const (
	settingsFileName = "govulncheck-settings.json"

	// maxModules and maxModuleDepth bound the workspace walk, so a pathological
	// repository cannot turn one scan into thousands of toolchain runs.
	maxModules     = 32
	maxModuleDepth = 8

	// maxOutput caps the child's JSON stream. The real stream for a large
	// module is a few megabytes; 256 MiB is far above it and still bounded.
	maxOutput = 256 << 20
	// maxStderr is how much of the child's stderr is kept for the error
	// message.
	maxStderr = 64 << 10
	// childWaitDelay bounds how long Wait waits for the pipes to close after
	// the process group is killed.
	childWaitDelay = 5 * time.Second
)

// ErrGoUnavailable is returned when the enrichment is on but no `go`
// executable is on PATH. Findings stay `unknown` and the scan succeeds.
var ErrGoUnavailable = errors.New("govulncheck: no go executable on PATH")

// Status is the read-only view the API and the CLI render.
type Status struct {
	// Enabled is the stored opt-in setting.
	Enabled bool
	// Available reports whether a `go` executable was found on PATH.
	Available bool
	// Error explains a failed probe, empty when the toolchain was found.
	Error string
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir holds the opt-in setting. It is the directory the EPSS feed and
	// the release check also store their consent in.
	DataDir string
	// Timeout bounds one scan's analysis across all modules. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// LookPath finds an executable on PATH; tests replace it.
	LookPath func(string) (string, error)
	// Executable is the binary the child process runs; empty means
	// os.Executable(). Tests and the real-tag test point it at a built
	// bastion, or at a stand-in such as `sleep`.
	Executable string
	// ChildArgs builds the child's arguments for one module directory. Empty
	// means the hidden internal-govulncheck subcommand.
	ChildArgs func(dir string) []string
	// Run analyzes one module directory. Empty means the child process. Tests
	// replace it with recorded output.
	Run func(ctx context.Context, dir string) (map[string]map[string]bool, error)
	// Logger receives debug records for an unreadable setting.
	Logger *slog.Logger
}

// Service runs the reachability enrichment and stores its opt-in setting. It
// is safe for concurrent use.
type Service struct {
	dataDir   string
	timeout   time.Duration
	lookPath  func(string) (string, error)
	exec      string
	childArgs func(dir string) []string
	run       func(ctx context.Context, dir string) (map[string]map[string]bool, error)
	log       *slog.Logger

	// enabled mirrors the stored setting. Lookup reads it per scan, so it must
	// not touch the filesystem.
	enabled atomic.Bool
}

// New wires a Service with production defaults for the unset seams. It reads
// the stored setting and performs no analysis.
func New(cfg Config) *Service {
	lookPath := cfg.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	executable := cfg.Executable
	if executable == "" {
		if path, err := os.Executable(); err == nil {
			executable = path
		}
	}
	childArgs := cfg.ChildArgs
	if childArgs == nil {
		childArgs = func(dir string) []string {
			return []string{InternalCommand, "--dir", dir}
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		dataDir:   cfg.DataDir,
		timeout:   timeout,
		lookPath:  lookPath,
		exec:      executable,
		childArgs: childArgs,
		log:       logger,
	}
	s.run = cfg.Run
	if s.run == nil {
		s.run = s.runChild
	}
	s.enabled.Store(s.readSetting())
	return s
}

// Name is the stable scanner id stored in scanner_runs.
func (s *Service) Name() string { return Name }

// Version identifies the analyzer's release for scanner_runs.
func (s *Service) Version() string { return libraryVersion }

// Enabled reports the stored setting. It never touches the network.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	return s.enabled.Load()
}

// SetEnabled stores the user's answer. Only the UI calls this; the CLI only
// reads. Turning it on affects the next scan, never a running one.
func (s *Service) SetEnabled(enabled bool) error {
	if s.dataDir == "" {
		return errors.New("govulncheck: data directory is required")
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("govulncheck: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("govulncheck: encode settings: %w", err)
	}
	path := filepath.Join(s.dataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("govulncheck: store settings: %w", err)
	}
	s.enabled.Store(enabled)
	return nil
}

// Status probes the toolchain and returns the setting with it. The probe is a
// PATH lookup only, so the API and doctor never wait on a process.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	status := Status{Enabled: s.enabled.Load()}
	if _, err := s.lookPath("go"); err != nil {
		status.Error = ErrGoUnavailable.Error()
		return status
	}
	status.Available = true
	return status
}

// Snapshot is Status under the name the doctor report uses.
func (s *Service) Snapshot() Status { return s.Status() }

// Enrich classifies the Go vulnerability findings of one workspace. ran is
// false when nothing was attempted: the setting is off, the workspace has no Go
// vulnerability finding, or it contains no Go module.
//
// Every Go vulnerability finding starts as unknown, so a module that fails
// analysis degrades to unknown rather than keeping a stale answer. One deadline
// covers all modules. A missing toolchain returns ErrGoUnavailable; a
// per-module failure is returned after the modules that succeeded were applied.
func (s *Service) Enrich(ctx context.Context, dir string, fs []findings.Finding) (ran bool, err error) {
	if !s.Enabled() || dir == "" {
		return false, nil
	}
	if !hasGoVulnerability(fs) {
		return false, nil
	}
	modules := moduleDirs(dir)
	if len(modules) == 0 {
		return false, nil
	}

	for i := range fs {
		if isGoVulnerability(fs[i]) {
			fs[i].Reachability = findings.ReachabilityUnknown
		}
	}

	if _, lookErr := s.lookPath("go"); lookErr != nil {
		return true, ErrGoUnavailable
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	states := make(map[string]map[string]bool)
	var failures []error
	for _, module := range modules {
		if ctx.Err() != nil {
			failures = append(failures, fmt.Errorf("%s: %w", module, ctx.Err()))
			break
		}
		entries, analyzeErr := s.run(ctx, module)
		if analyzeErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", module, analyzeErr))
			continue
		}
		for id, byModule := range entries {
			target := states[id]
			if target == nil {
				target = make(map[string]bool)
				states[id] = target
			}
			for modulePath, reachable := range byModule {
				target[modulePath] = target[modulePath] || reachable
			}
		}
	}

	for i := range fs {
		if !isGoVulnerability(fs[i]) {
			continue
		}
		fs[i].Reachability = classify(fs[i], states)
	}
	return true, errors.Join(failures...)
}

// runChild runs the analyzer in a child process and decodes its JSON stream.
// The child is bastion itself with the hidden internal-govulncheck subcommand,
// so the parent can kill the whole `go` process tree it starts.
func (s *Service) runChild(ctx context.Context, dir string) (map[string]map[string]bool, error) {
	if s.exec == "" {
		return nil, errors.New("govulncheck: bastion executable is unknown")
	}
	// The executable is bastion itself (or a test stand-in), never input.
	cmd := exec.Command(s.exec, s.childArgs(dir)...) // #nosec G204 -- fixed analyzer child, not user input
	// The environment is built from an allowlist: the child needs a toolchain
	// and its caches, nothing else (no tokens, no cloud credentials).
	cmd.Env = childEnv(os.Environ())
	cmd.WaitDelay = childWaitDelay
	setProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("govulncheck: stdout pipe: %w", err)
	}
	stderr := &tailBuffer{max: maxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("govulncheck: start: %w", err)
	}

	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	// A child that outlives the deadline (or a canceled scan) is killed as a
	// group: the `go` toolchain spawns compilers that would otherwise survive.
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			killProcessGroup(cmd)
		case <-watcherDone:
		}
	}()

	states, parseErr := parseLimited(stdout)
	close(watcherDone)
	if parseErr != nil {
		// Stop the child before waiting: it may still be writing.
		killProcessGroup(cmd)
	}
	<-done

	if parseErr != nil {
		return nil, fmt.Errorf("govulncheck: %w%s", parseErr, stderr.suffix())
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("govulncheck: %w%s", ctx.Err(), stderr.suffix())
	}
	if waitErr != nil {
		return nil, fmt.Errorf("govulncheck: %w%s", waitErr, stderr.suffix())
	}
	return states, nil
}

// parseLimited decodes the child's stream with a hard size cap. Exceeding it is
// an error rather than a silent truncation, so a broken analyzer cannot look
// like a clean run.
func parseLimited(r io.Reader) (map[string]map[string]bool, error) {
	limited := &io.LimitedReader{R: r, N: maxOutput + 1}
	states, err := parse(limited)
	if err != nil {
		return nil, err
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("output exceeds %d MiB", maxOutput>>20)
	}
	return states, nil
}

// childEnv builds the child's environment from an allowlist. Only what the Go
// toolchain needs to resolve and build modules survives; everything else in
// bastion's environment (tokens, cloud credentials, proxy secrets) is dropped.
// The toolchain behaviour is pinned so the child cannot pick up a workspace, a
// toolchain download or telemetry from the caller's environment.
//
// A forced GOFLAGS="" is treated as unset by `go env GOFLAGS` (verified), so
// the empty value clears inherited flags rather than setting an empty one.
func childEnv(parent []string) []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true,
		"GOPATH": true, "GOMODCACHE": true, "GOCACHE": true,
		"GOPROXY": true, "GOSUMDB": true,
	}
	values := make(map[string]string, len(allowed)+6)
	for _, kv := range parent {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !allowed[key] {
			continue
		}
		values[key] = value
	}
	for key, value := range map[string]string{
		"GOTOOLCHAIN": "local",
		"CGO_ENABLED": "0",
		"GOWORK":      "off",
		"GOFLAGS":     "",
		"GOENV":       "off",
		"GOTELEMETRY": "off",
	} {
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

// classify maps one finding onto the analysis: an advisory id or one of its
// aliases with a call trace is reachable; an advisory govulncheck reported only
// at package or module level is unreachable; anything else is unknown. States
// are keyed by module path, and a finding's package is matched by module-path
// prefix (the package `golang.org/x/net/html` belongs to module
// `golang.org/x/net`).
func classify(f findings.Finding, states map[string]map[string]bool) findings.Reachability {
	ids := append([]string{f.RuleID}, f.Aliases...)
	answered, reachable := false, false
	for _, raw := range ids {
		id := normalizeID(raw)
		if id == "" {
			continue
		}
		byModule, ok := states[id]
		if !ok {
			continue
		}
		matched := false
		if f.PackageName != "" {
			for modulePath, called := range byModule {
				if modulePath == "" {
					continue
				}
				if f.PackageName == modulePath || strings.HasPrefix(f.PackageName, modulePath+"/") {
					matched = true
					answered = true
					reachable = reachable || called
				}
			}
		}
		// A finding without a package cannot be attributed to one module; any
		// answer for the advisory is better than none.
		if !matched && f.PackageName == "" {
			for _, called := range byModule {
				answered = true
				reachable = reachable || called
			}
		}
	}
	switch {
	case !answered:
		return findings.ReachabilityUnknown
	case reachable:
		return findings.ReachabilityReachable
	default:
		return findings.ReachabilityUnreachable
	}
}

// normalizeID makes advisory ids comparable: scanners and the database disagree
// on case and whitespace (CVE vs cve, GHSA ids).
func normalizeID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// isGoVulnerability reports whether a finding is a Go dependency vulnerability
// the enrichment can classify. Trivy normalizes gomod, gobinary and go to "go".
func isGoVulnerability(f findings.Finding) bool {
	return f.Type == findings.TypeVulnerability && f.Ecosystem == "go"
}

func hasGoVulnerability(fs []findings.Finding) bool {
	for _, f := range fs {
		if isGoVulnerability(f) {
			return true
		}
	}
	return false
}

// moduleDirs lists the directories of a workspace that hold a real go.mod. The
// walk is bounded in depth and count, never follows a path outside the
// workspace, and ignores vendor trees, test fixtures and hidden directories.
func moduleDirs(root string) []string {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil
	}
	rootReal, err = filepath.Abs(rootReal)
	if err != nil {
		return nil
	}

	var dirs []string
	_ = filepath.WalkDir(rootReal, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is skipped: reachability is an enrichment,
			// and the scan's findings do not depend on it.
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if depth(path, rootReal) > maxModuleDepth {
			return filepath.SkipDir
		}
		name := entry.Name()
		if path != rootReal && (strings.HasPrefix(name, ".") || skipDir[name]) {
			return filepath.SkipDir
		}
		// A symlinked directory must not lead outside the workspace.
		resolved, linkErr := filepath.EvalSymlinks(path)
		if linkErr != nil {
			return filepath.SkipDir
		}
		resolved, linkErr = filepath.Abs(resolved)
		if linkErr != nil {
			return filepath.SkipDir
		}
		if resolved != rootReal && !strings.HasPrefix(resolved, rootReal+string(filepath.Separator)) {
			return filepath.SkipDir
		}
		// A symlinked go.mod is not a module file: Lstat sees the link itself,
		// so it never resolves to something outside the workspace.
		info, statErr := os.Lstat(filepath.Join(path, "go.mod"))
		if statErr != nil || !info.Mode().IsRegular() {
			return nil
		}
		dirs = append(dirs, resolved)
		if len(dirs) >= maxModules {
			return filepath.SkipAll
		}
		return nil
	})
	sort.Strings(dirs)
	return dirs
}

// depth is how many path elements separate path from root; 0 for root itself.
func depth(path, root string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

// skipDir names directories that never hold a module bastion should analyze.
var skipDir = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	"testdata":     true,
}

// tailBuffer keeps the last max bytes written to it. stderr is only read for an
// error message, and the interesting part is the end.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

// suffix renders the buffered stderr for an error message.
func (b *tailBuffer) suffix() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.TrimSpace(string(b.buf))
	if text == "" {
		return ""
	}
	return ": " + text
}

// settingsFile is the stored opt-in setting.
type settingsFile struct {
	Enabled bool `json:"enabled"`
}

// readSetting returns false for a missing or unreadable file: the enrichment is
// opt-in, so anything short of an explicit "true" means off.
func (s *Service) readSetting() bool {
	if s.dataDir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, settingsFileName))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.log.Debug("govulncheck: read settings", "error", err)
		}
		return false
	}
	var file settingsFile
	if err := json.Unmarshal(data, &file); err != nil {
		s.log.Debug("govulncheck: decode settings", "error", err)
		return false
	}
	return file.Enabled
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory, so a crash leaves the old file rather than a truncated one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
