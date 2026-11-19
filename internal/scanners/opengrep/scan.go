package opengrep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
)

// Name is the stable scanner id stored in scanner_runs.
const Name = "opengrep"

const (
	// DefaultTimeout bounds one scan's wall-clock time. A cold run compiles the
	// rule set, which takes tens of seconds on its own.
	DefaultTimeout = 10 * time.Minute

	// perRuleTimeoutSeconds is the per-rule/per-file budget passed to
	// opengrep. A pathological file is skipped instead of stalling the scan.
	perRuleTimeoutSeconds = 30
	// maxTargetBytes is the largest file opengrep reads.
	maxTargetBytes = 1_000_000

	// maxOutput caps opengrep's JSON stream. A large repository's report is a
	// few megabytes; 64 MiB is far above it and still bounded.
	maxOutput = 64 << 20
	// maxStderr is how much of opengrep's stderr is kept for the error message.
	maxStderr = 64 << 10
	// childWaitDelay bounds how long Wait waits for the pipes to close after
	// the process group is killed.
	childWaitDelay = 5 * time.Second

	// maxResults caps the number of parsed results. The JSON is untrusted, so
	// a hostile report cannot turn into an unbounded findings list.
	maxResults = 10_000

	// maxTitleRunes bounds a finding's title, which comes from an untrusted
	// rule message.
	maxTitleRunes = 200

	// rulesDirName is the directory the rule set is extracted to inside the
	// module directory. It is also the prefix opengrep puts on check ids when
	// the config is given as this relative directory.
	rulesDirName = "rules"
	// ruleIDPrefix is what opengrep prepends to a check id for a directory
	// config named rulesDirName. It is stripped so rule ids stay stable and
	// match the upstream rule id.
	ruleIDPrefix = rulesDirName + "."
)

// scanModule is the part of Service a Scanner needs. Keeping it an interface
// lets tests stub the enabled state and the runner without a download.
type scanModule interface {
	Enabled() bool
	Status() Status
	EnsureInstalled(ctx context.Context) error
	run(ctx context.Context, dir string) (runOutput, error)
}

// Scanner adapts the downloaded module to the scanners.Scanner interface.
type Scanner struct {
	module scanModule
	// force runs the scanner even when the stored setting is off. It is what
	// `bastion scan --sast` uses: the flag applies to that run only.
	force bool
}

// NewScanner returns an Opengrep scanner backed by module. It runs only when
// the stored setting is on.
func NewScanner(module *Service) *Scanner { return &Scanner{module: module} }

// NewScannerForced returns an Opengrep scanner that runs regardless of the
// stored setting.
func NewScannerForced(module *Service) *Scanner { return &Scanner{module: module, force: true} }

// Name returns the stable scanner id.
func (*Scanner) Name() string { return Name }

// Version returns the pinned Opengrep release.
func (*Scanner) Version() string { return Version }

// Supports reports whether Opengrep can scan target kind k. It reads a working
// tree, which local paths and checked-out repositories provide; images have no
// source tree to analyze. With the setting off it supports nothing, so a scan
// is byte-for-byte what it was before SAST existed.
func (s *Scanner) Supports(k sources.TargetKind) bool {
	if s == nil || s.module == nil {
		return false
	}
	if k != sources.KindPath && k != sources.KindRepo {
		return false
	}
	return s.force || s.module.Enabled()
}

// Scan runs opengrep over ws and returns its native JSON. The output is
// untrusted: Normalize validates every path and value before it becomes a
// finding.
func (s *Scanner) Scan(ctx context.Context, ws *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
	if s == nil || s.module == nil {
		return nil, errors.New("opengrep: module is not configured")
	}
	if ws == nil || ws.Dir == "" {
		return nil, errors.New("opengrep: workspace directory is required")
	}
	// A scan that starts while the UI's opt-in download is running waits for
	// it; a failed earlier download is retried here rather than failing the
	// scan with a stale error.
	if err := s.module.EnsureInstalled(ctx); err != nil {
		return nil, fmt.Errorf("opengrep: install module: %w", err)
	}

	status := s.module.Status()
	switch status.State {
	case StateInstalled:
	case StateChecksumBad:
		return nil, fmt.Errorf("opengrep: downloaded module is unusable: %s", status.Error)
	default:
		return nil, errors.New("opengrep: module is not installed; enable SAST to download it")
	}

	run, err := s.module.run(ctx, ws.Dir)
	if err != nil {
		return nil, err
	}
	raw := &scanners.RawResult{
		Scanner:      Name,
		Version:      Version,
		WorkspaceDir: ws.Dir,
		Warnings:     run.warnings,
	}
	// A truncated or timed-out stream is not valid JSON; the warning says the
	// run was partial, and Normalize then yields no findings rather than an
	// error.
	if !run.timedOut && !run.truncated {
		raw.Raw = run.stdout
	}
	return raw, nil
}

// runOutput is one child run's captured result.
type runOutput struct {
	stdout    []byte
	timedOut  bool
	truncated bool
	warnings  []string
}

// run executes opengrep with a minimal environment and hard budgets. A wall
// clock timeout or an oversized output stream kills the whole process group
// and becomes a warning, not an error, so partial coverage is visible without
// failing the scan. A canceled scan returns the caller's error.
func (s *Service) run(ctx context.Context, dir string) (runOutput, error) {
	binary := s.executable
	if binary == "" {
		binary = s.BinaryPath()
	}
	if binary == "" {
		return runOutput{}, errors.New("opengrep: executable path is unknown")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return runOutput{}, fmt.Errorf("opengrep: resolve workspace: %w", err)
	}

	// The executable is the downloaded module (or a test stand-in), never
	// input.
	cmd := exec.Command(binary, s.args(absDir)...) // #nosec G204 -- fixed module binary, not user input
	// opengrep's config is the relative rules directory, and the child runs
	// from the module directory: that keeps the check-id prefix stable
	// ("rules.") and strips to the upstream rule id.
	cmd.Dir = s.Dir()
	cmd.Env = childEnv(os.Environ())
	cmd.WaitDelay = childWaitDelay
	setProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return runOutput{}, fmt.Errorf("opengrep: stdout pipe: %w", err)
	}
	stderr := &tailBuffer{max: maxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return runOutput{}, fmt.Errorf("opengrep: start: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// A child that outlives the deadline (or a canceled scan) is killed as a
	// group, so anything it spawned goes too.
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			killProcessGroup(cmd)
		case <-watcherDone:
		}
	}()

	// The pipe must be drained before Wait: os/exec closes it on Wait, so
	// reading concurrently with Wait would race. The reader is the only
	// consumer and returns once the child exits or the cap is reached.
	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(stdout, s.maxOutput+1))
		readDone <- readResult{data: data, err: err}
	}()
	read := <-readDone
	data := read.data
	truncated := int64(len(data)) > s.maxOutput
	if truncated {
		data = data[:s.maxOutput]
		// Stop the child before waiting: it may still be writing.
		killProcessGroup(cmd)
	}
	close(watcherDone)
	waitErr := cmd.Wait()

	// The caller's cancellation wins over every other outcome: the scan is
	// being canceled, not degraded.
	if ctx.Err() != nil {
		return runOutput{}, fmt.Errorf("opengrep: %w%s", ctx.Err(), stderr.suffix())
	}

	out := runOutput{stdout: data}
	switch {
	case runCtx.Err() != nil:
		out.timedOut = true
		out.warnings = append(out.warnings,
			fmt.Sprintf("opengrep timed out after %s; results are partial", s.timeout))
	case truncated:
		out.truncated = true
		out.warnings = append(out.warnings,
			fmt.Sprintf("opengrep output exceeded %d MiB; results are partial", s.maxOutput>>20))
	case read.err != nil:
		return runOutput{}, fmt.Errorf("opengrep: read output: %w%s", read.err, stderr.suffix())
	case waitErr != nil:
		return runOutput{}, fmt.Errorf("opengrep: %w%s", waitErr, stderr.suffix())
	}
	return out, nil
}

// args builds the opengrep command line. It uses the semgrep-compatible flags
// this pinned release actually has: --metrics does not exist in v1.33.1, so
// version checking is disabled instead.
func (s *Service) args(dir string) []string {
	return []string{
		"scan",
		"--json",
		"--disable-version-check",
		"--config", rulesDirName,
		"--timeout", fmt.Sprint(perRuleTimeoutSeconds),
		"--max-target-bytes", fmt.Sprint(maxTargetBytes),
		"--exclude", ".git",
		"--exclude", "node_modules",
		"--exclude", "vendor",
		dir,
	}
}

// childEnv builds the child's environment from an allowlist. opengrep needs a
// PATH, a home for its cache and a temp directory; everything else in
// bastion's environment (tokens, cloud credentials, proxy secrets) is dropped.
func childEnv(parent []string) []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true,
		"TMP": true, "TEMP": true, "SystemRoot": true,
	}
	values := make(map[string]string, len(allowed))
	for _, kv := range parent {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !allowed[key] {
			continue
		}
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

// jsonReport is the part of opengrep's JSON document bastion reads. The
// document is untrusted, so only the fields the model needs are decoded.
type jsonReport struct {
	Results []jsonResult      `json:"results"`
	Errors  []json.RawMessage `json:"errors"`
}

type jsonResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
		Metadata struct {
			CWE cweList `json:"cwe"`
		} `json:"metadata"`
	} `json:"extra"`
}

// cweList decodes the rule's cwe metadata. Rules publish it as one string
// ("CWE-89: Improper Neutralization...") or as a list of such strings; any
// other shape is ignored rather than failing the scan, because the metadata is
// free-form and has changed shape upstream before.
type cweList []string

func (c *cweList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*c = cweList{single}
		return nil
	}
	var list []any
	if err := json.Unmarshal(data, &list); err != nil {
		return nil
	}
	out := make(cweList, 0, len(list))
	for _, entry := range list {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	*c = out
	return nil
}

// parse decodes opengrep's report into bastion findings. Paths outside root
// are skipped and counted in a warning; they are never turned into findings.
func parse(data []byte, root string, asset findings.Asset) ([]findings.Finding, []string, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("opengrep: report is empty")
	}
	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("opengrep: decode report: %w", err)
	}

	var warnings []string
	if len(report.Results) > maxResults {
		warnings = append(warnings,
			fmt.Sprintf("opengrep returned %d results; only the first %d are kept", len(report.Results), maxResults))
		report.Results = report.Results[:maxResults]
	}
	if len(report.Errors) > 0 {
		warnings = append(warnings,
			fmt.Sprintf("opengrep reported %d scan errors; results are partial", len(report.Errors)))
	}

	found := make([]findings.Finding, 0, len(report.Results))
	skipped := 0
	for _, result := range report.Results {
		rel, ok := relativePath(root, result.Path)
		if !ok {
			skipped++
			continue
		}
		id := ruleID(result.CheckID)
		if id == "" {
			skipped++
			continue
		}
		location := rel
		if result.Start.Line > 0 {
			location = fmt.Sprintf("%s:%d", rel, result.Start.Line)
		}
		title := truncateRunes(strings.TrimSpace(result.Extra.Message), maxTitleRunes)
		if title == "" {
			title = id
		}
		snippet := snippetHash(result.Extra.Lines)
		if snippet == "" {
			// No snippet to anchor on: fall back to the line, so two
			// occurrences of the same rule in one file stay distinct.
			snippet = snippetHash(fmt.Sprintf("line:%d", result.Start.Line))
		}
		f := findings.Finding{
			AssetID:     asset.ID,
			Type:        findings.TypeSAST,
			RuleID:      id,
			Severity:    severityFromString(result.Extra.Severity),
			Title:       title,
			Location:    location,
			CWE:         findings.NormalizeCWEIDs(result.Extra.Metadata.CWE),
			Scanner:     Name,
			SnippetHash: snippet,
		}
		f.Fingerprint = findings.Fingerprint(asset.ID, f)
		found = append(found, f)
	}
	if skipped > 0 {
		warnings = append(warnings,
			fmt.Sprintf("skipped %d result(s) outside the workspace or without a rule id", skipped))
	}
	findings.SortFindings(found)
	return found, warnings, nil
}

// Normalize maps opengrep's JSON into bastion's model. It also appends any
// partial-coverage warnings to raw, so the caller can surface them beside the
// scanner run.
func (s *Scanner) Normalize(raw *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	if raw == nil {
		return nil, nil, errors.New("opengrep: raw result is required")
	}
	// A truncated or timed-out run carries no parseable report; its warning is
	// the result.
	if len(raw.Raw) == 0 {
		if len(raw.Warnings) == 0 {
			return nil, nil, errors.New("opengrep: report is empty")
		}
		return nil, nil, nil
	}
	found, warnings, err := parse(raw.Raw, raw.WorkspaceDir, asset)
	if err != nil {
		return nil, nil, err
	}
	raw.Warnings = append(raw.Warnings, warnings...)
	return found, nil, nil
}

// ruleID strips opengrep's config-directory prefix from a check id.
func ruleID(checkID string) string {
	id := strings.TrimSpace(checkID)
	if strings.HasPrefix(id, ruleIDPrefix) {
		return strings.TrimPrefix(id, ruleIDPrefix)
	}
	return id
}

// severityFromString maps opengrep's rule severity onto bastion's scale.
func severityFromString(value string) findings.Severity {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ERROR":
		return findings.SeverityHigh
	case "WARNING":
		return findings.SeverityMedium
	case "INFO":
		return findings.SeverityLow
	default:
		return findings.SeverityUnknown
	}
}

// relativePath makes a result path relative to root and rejects absolute paths
// and paths that escape it.
func relativePath(root, value string) (string, bool) {
	if root == "" || strings.TrimSpace(value) == "" {
		return "", false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(value)
	if !filepath.IsAbs(path) {
		path = filepath.Join(rootAbs, filepath.FromSlash(path))
	}
	rel, err := filepath.Rel(rootAbs, filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// snippetHash digests the normalized matched snippet, so a finding keeps its
// fingerprint when unrelated lines shift.
func snippetHash(lines string) string {
	normalized := strings.Join(strings.Fields(lines), " ")
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// truncateRunes cuts s to at most limit runes, appending an ellipsis when it
// was cut. The message is untrusted and may be arbitrarily long.
func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}
