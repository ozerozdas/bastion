// Package opengrep downloads and runs bastion's opt-in SAST module.
//
// Opengrep has no Go library, so it is a downloaded module (ADR-002): a pinned
// release binary and a pinned rule set, both checksum-verified before they are
// used. Nothing is downloaded unless the user opts in; the core scanners work
// without this package.
package opengrep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Version is the pinned Opengrep release.
	Version = "v1.33.1"

	// rulesCommit is the pinned opengrep-rules revision.
	rulesCommit = "f1d2b562b414783763fd02a6ed2736eaed622efa"
	// rulesSHA256 is the digest of the codeload tarball for rulesCommit.
	rulesSHA256 = "9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d"

	// defaultDownloadBaseURL is the GitHub release asset host for Version.
	defaultDownloadBaseURL = "https://github.com/opengrep/opengrep/releases/download/" + Version
	// defaultRulesURL is the pinned rules tarball.
	defaultRulesURL = "https://codeload.github.com/opengrep/opengrep-rules/tar.gz/" + rulesCommit

	// moduleDirName is the versioned directory inside <cache>/modules.
	moduleDirName = "opengrep-" + Version

	// settingsFileName holds the opt-in choice in the data directory, next to
	// the EPSS and reachability settings.
	settingsFileName = "opengrep-settings.json"

	// maxBinaryBytes caps the binary download. The release is ~47 MB.
	maxBinaryBytes = 256 << 20
	// maxRulesBytes caps the rules tarball. The pinned one is ~1.1 MB.
	maxRulesBytes = 64 << 20
	// maxRuleFileBytes caps one extracted rule file; real rule files are a few
	// kilobytes.
	maxRuleFileBytes = 4 << 20
	// maxRulesTotalBytes caps the whole extracted rule set, so an archive with
	// a huge number of small files cannot fill the disk.
	maxRulesTotalBytes = 128 << 20

	// downloadTimeout bounds one download. The binary is tens of megabytes.
	downloadTimeout = 5 * time.Minute
)

// asset is one pinned release binary.
type asset struct {
	name   string
	sha256 string
}

// releaseAssets is the compiled-in platform table. A platform that is absent
// has no pinned binary and the module reports a clear error instead of
// downloading something unverified.
var releaseAssets = map[string]asset{
	"darwin/arm64":  {name: "opengrep_osx_arm64", sha256: "a17c1881bb40e3214266a7a291cf4f2ae3bc56c1715628b5712d2ec816bc3e2d"},
	"darwin/amd64":  {name: "opengrep_osx_x86", sha256: "c3bd18e0d898d44e28419d95dad57c8928bb46ab32889a0ee1f72a87ad9627af"},
	"linux/arm64":   {name: "opengrep_manylinux_aarch64", sha256: "d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf"},
	"linux/amd64":   {name: "opengrep_manylinux_x86", sha256: "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808"},
	"windows/amd64": {name: "opengrep_windows_x86.exe", sha256: "132e606e071bdd3928286fddc893198a6106a90820d46e21197e0ace1a23e0c1"},
}

// State is the installed state of the module.
type State string

// Module states the doctor and the API render.
const (
	// StateNotInstalled means the binary or the rules are missing. Nothing
	// has been downloaded yet, or a previous install did not finish.
	StateNotInstalled State = "not_installed"
	// StateInstalled means both the binary and the rules are present and the
	// binary matches its pinned digest.
	StateInstalled State = "installed"
	// StateChecksumBad means the binary on disk does not match the pinned
	// digest. It is never run; Install replaces it.
	StateChecksumBad State = "checksum_bad"
)

// Status is the read-only view the doctor and the API render.
type Status struct {
	// Enabled is the stored opt-in setting.
	Enabled bool
	// State is the installed state.
	State State
	// Version is the pinned Opengrep release.
	Version string
	// Dir is the versioned module directory.
	Dir string
	// BinaryPath is the downloaded executable.
	BinaryPath string
	// RulesDir is the extracted rule set.
	RulesDir string
	// Installing reports whether a download is running.
	Installing bool
	// Error explains a checksum mismatch or an unreadable module.
	Error string
	// InstallError is why the last download failed; it clears on success.
	InstallError string
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir holds the opt-in setting. It is the directory the EPSS feed and
	// the reachability enrichment also store their consent in.
	DataDir string
	// ModulesDir is <cache>/modules, the parent of the versioned module
	// directory. app.Paths.ModulesDir provides it.
	ModulesDir string
	// Version is the bastion build version for the User-Agent header.
	Version string
	// GOOS and GOARCH select the pinned asset; empty means the build target.
	GOOS   string
	GOARCH string

	// DownloadBaseURL overrides the release asset host, up to the tag.
	DownloadBaseURL string
	// RulesURL overrides the rules tarball location.
	RulesURL string
	// HTTPClient lets tests point at an httptest TLS server. Its timeout is
	// replaced.
	HTTPClient *http.Client

	// BinarySHA256 and RulesSHA256 override the pinned digests; tests only.
	BinarySHA256 string
	RulesSHA256  string
	// MaxBinaryBytes and MaxRulesBytes override the download caps; tests only.
	MaxBinaryBytes int64
	MaxRulesBytes  int64

	// Timeout bounds one scan's wall-clock time. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxOutputBytes caps the child's JSON stream. Zero means maxOutput.
	MaxOutputBytes int64
	// Executable overrides the binary a scan runs; tests use a stand-in.
	Executable string

	// Spawn runs a background install. It defaults to `go f()`; tests run it
	// inline so an assertion after SetEnabled sees the result.
	Spawn func(func())
	// Install overrides the downloader; tests use a stub so no request is
	// made. Empty means the real pinned download.
	Install func(ctx context.Context) error
}

// Service owns the downloaded module and its opt-in setting. It is safe for
// concurrent use.
type Service struct {
	dataDir    string
	modulesDir string
	goos       string
	goarch     string
	binaryURL  string
	rulesURL   string
	client     *http.Client
	agent      string
	binarySHA  string
	rulesSHA   string
	binaryCap  int64
	rulesCap   int64
	timeout    time.Duration
	maxOutput  int64
	executable string
	spawn      func(func())
	install    func(context.Context) error

	// enabled mirrors the stored setting. Supports reads it per scan, so it
	// must not touch the filesystem.
	enabled atomic.Bool

	// installStartMu guards installDone: the channel is the single-flight
	// marker for a download, so a waiter can select on its own context instead
	// of blocking on a mutex.
	installStartMu sync.Mutex
	installDone    chan struct{}
	// installing and installErr are read by Status without taking
	// installStartMu, which is held only while a download starts.
	installing atomic.Bool
	installErr atomic.Value // string
}

// New wires a Service with production defaults for the unset seams. It reads
// the stored setting and performs no network call.
func New(cfg Config) *Service {
	goos := cfg.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := cfg.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	baseURL := strings.TrimRight(cfg.DownloadBaseURL, "/")
	if baseURL == "" {
		baseURL = defaultDownloadBaseURL
	}
	rulesURL := cfg.RulesURL
	if rulesURL == "" {
		rulesURL = defaultRulesURL
	}
	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	client.Timeout = downloadTimeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing non-HTTPS redirect to %q", req.URL.Redacted())
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	agent := "bastion"
	if cfg.Version != "" {
		agent = "bastion/" + cfg.Version
	}
	binarySHA := cfg.BinarySHA256
	if binarySHA == "" {
		if a, ok := releaseAssets[goos+"/"+goarch]; ok {
			binarySHA = a.sha256
		}
	}
	rulesSHA := cfg.RulesSHA256
	if rulesSHA == "" {
		rulesSHA = rulesSHA256
	}
	binaryCap := cfg.MaxBinaryBytes
	if binaryCap <= 0 {
		binaryCap = maxBinaryBytes
	}
	rulesCap := cfg.MaxRulesBytes
	if rulesCap <= 0 {
		rulesCap = maxRulesBytes
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	outputCap := cfg.MaxOutputBytes
	if outputCap <= 0 {
		outputCap = maxOutput
	}
	spawn := cfg.Spawn
	if spawn == nil {
		spawn = func(f func()) { go f() }
	}
	s := &Service{
		dataDir:    cfg.DataDir,
		modulesDir: cfg.ModulesDir,
		goos:       goos,
		goarch:     goarch,
		binaryURL:  baseURL + "/" + binaryName(goos, goarch),
		rulesURL:   rulesURL,
		client:     client,
		agent:      agent,
		binarySHA:  binarySHA,
		rulesSHA:   rulesSHA,
		binaryCap:  binaryCap,
		rulesCap:   rulesCap,
		timeout:    timeout,
		maxOutput:  outputCap,
		executable: cfg.Executable,
		spawn:      spawn,
	}
	s.install = cfg.Install
	if s.install == nil {
		s.install = s.Install
	}
	s.enabled.Store(s.readSetting())
	return s
}

// Dir is the versioned module directory.
func (s *Service) Dir() string {
	return filepath.Join(s.modulesDir, moduleDirName)
}

// BinaryPath is the executable inside the module directory.
func (s *Service) BinaryPath() string {
	return filepath.Join(s.Dir(), binaryFileName(s.goos))
}

// RulesDir is the extracted rule set inside the module directory.
func (s *Service) RulesDir() string {
	return filepath.Join(s.Dir(), rulesDirName)
}

// Enabled reports the stored setting. It never touches the network.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	return s.enabled.Load()
}

// SetEnabled stores the user's answer and, when it turns SAST on, starts the
// one-time download in the background. Turning it off never cancels a running
// download; it only keeps future scans from using the module.
func (s *Service) SetEnabled(enabled bool) error {
	if s.dataDir == "" {
		return errors.New("opengrep: data directory is required")
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("opengrep: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("opengrep: encode settings: %w", err)
	}
	path := filepath.Join(s.dataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("opengrep: store settings: %w", err)
	}
	s.enabled.Store(enabled)
	if enabled && s.Status().State != StateInstalled {
		// Report the download immediately, before the goroutine is scheduled,
		// so a status read straight after the PUT says "installing".
		s.installing.Store(true)
		s.spawn(func() { _ = s.EnsureInstalled(context.Background()) })
	}
	return nil
}

// EnsureInstalled downloads the module when it is not installed. Concurrent
// callers share one download, and a caller whose context ends stops waiting
// instead of blocking on the shared run.
func (s *Service) EnsureInstalled(ctx context.Context) error {
	if s.Status().State == StateInstalled {
		return nil
	}

	s.installStartMu.Lock()
	if s.Status().State == StateInstalled {
		s.installStartMu.Unlock()
		return nil
	}
	if done := s.installDone; done != nil {
		s.installStartMu.Unlock()
		select {
		case <-done:
			if value := s.installErr.Load(); value != nil {
				if message, _ := value.(string); message != "" {
					return errors.New(message)
				}
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan struct{})
	s.installDone = done
	s.installing.Store(true)
	s.installErr.Store("")
	s.installStartMu.Unlock()

	err := s.install(ctx)

	s.installing.Store(false)
	if err != nil {
		s.installErr.Store(err.Error())
	} else {
		s.installErr.Store("")
	}
	s.installStartMu.Lock()
	s.installDone = nil
	s.installStartMu.Unlock()
	close(done)
	return err
}

// Snapshot is Status under the name the doctor report uses.
func (s *Service) Snapshot() Status { return s.Status() }

// Status reports the stored setting and the module's state. It hashes the
// binary every time, so a replaced file is always caught; the ~47 MB hash is a
// small cost next to the scan it guards.
func (s *Service) Status() Status {
	if s == nil {
		return Status{State: StateNotInstalled, Version: Version}
	}
	status := Status{
		Enabled:    s.enabled.Load(),
		State:      StateNotInstalled,
		Version:    Version,
		Installing: s.installing.Load(),
	}
	if s.modulesDir == "" {
		status.Error = "module directory is not configured"
		return status
	}
	status.Dir = s.Dir()
	status.BinaryPath = s.BinaryPath()
	status.RulesDir = s.RulesDir()
	if value := s.installErr.Load(); value != nil {
		status.InstallError, _ = value.(string)
	}

	info, err := os.Stat(s.BinaryPath())
	if errors.Is(err, os.ErrNotExist) {
		return status
	}
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !info.Mode().IsRegular() {
		status.Error = "binary is not a regular file"
		return status
	}
	if !dirHasFiles(s.RulesDir()) {
		status.Error = "rules are not installed"
		return status
	}

	sum, err := fileSHA256(s.BinaryPath())
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !strings.EqualFold(sum, s.binarySHA) {
		status.State = StateChecksumBad
		status.Error = fmt.Sprintf("binary checksum is %s, expected %s", sum, s.binarySHA)
		return status
	}
	status.State = StateInstalled
	return status
}

// Install downloads the pinned binary and rules into the module directory.
// It is idempotent: a verified install is left alone. A checksum mismatch
// removes the downloaded file and returns an error.
func (s *Service) Install(ctx context.Context) error {
	if s.modulesDir == "" {
		return errors.New("opengrep: module directory is required")
	}
	a, ok := releaseAssets[s.goos+"/"+s.goarch]
	if !ok {
		return fmt.Errorf("opengrep: no pinned binary for %s/%s (supported: %s)",
			s.goos, s.goarch, supportedPlatforms())
	}
	if s.binarySHA == "" {
		return fmt.Errorf("opengrep: no checksum for %s", a.name)
	}
	if s.Status().State == StateInstalled {
		return nil
	}

	dir := s.Dir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("opengrep: create module directory: %w", err)
	}

	// Prepare both downloads before either is committed, so a failed rules
	// download leaves no half-installed module behind.
	rulesTmp, err := s.fetch(ctx, s.rulesURL, s.rulesSHA, s.rulesCap, ".rules-*.tar.gz")
	if err != nil {
		return fmt.Errorf("opengrep: download rules: %w", err)
	}
	defer func() { _ = os.Remove(rulesTmp) }()

	rulesDirTmp, err := os.MkdirTemp(dir, ".rules-extract-*")
	if err != nil {
		return fmt.Errorf("opengrep: create rules directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(rulesDirTmp) }()
	if err := extractRules(rulesTmp, rulesDirTmp); err != nil {
		return fmt.Errorf("opengrep: extract rules: %w", err)
	}

	binaryTmp, err := s.fetch(ctx, s.binaryURL, s.binarySHA, s.binaryCap, ".opengrep-*")
	if err != nil {
		return fmt.Errorf("opengrep: download binary: %w", err)
	}
	defer func() { _ = os.Remove(binaryTmp) }()
	if err := os.Chmod(binaryTmp, 0o755); err != nil { //nolint:gosec // the module is an executable the user opted into.
		return fmt.Errorf("opengrep: set binary mode: %w", err)
	}

	if err := os.Rename(binaryTmp, s.BinaryPath()); err != nil {
		return fmt.Errorf("opengrep: install binary: %w", err)
	}
	if err := replaceDir(rulesDirTmp, s.RulesDir()); err != nil {
		// The binary alone is not a usable install; do not leave it behind.
		_ = os.Remove(s.BinaryPath())
		return fmt.Errorf("opengrep: install rules: %w", err)
	}
	return nil
}

// fetch downloads rawURL to a temporary file in the module directory, verifies
// its SHA-256 and returns its path. A mismatch or an oversized body removes the
// file before returning.
func (s *Service) fetch(ctx context.Context, rawURL, wantSHA string, limit int64, pattern string) (string, error) {
	if err := requireHTTPS(rawURL); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.Dir(), 0o750); err != nil {
		return "", fmt.Errorf("create module directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", s.agent)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("answered %s", resp.Status)
	}

	file, err := os.CreateTemp(s.Dir(), pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(name)
		}
	}()

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(resp.Body, limit+1))
	closeErr := file.Close()
	switch {
	case copyErr != nil:
		return "", copyErr
	case written > limit:
		return "", fmt.Errorf("download exceeds the %d byte limit", limit)
	case closeErr != nil:
		return "", closeErr
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(sum, wantSHA) {
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s", wantSHA, sum)
	}
	remove = false
	return name, nil
}

// fileSHA256 hashes one file.
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path) //nolint:gosec // path is inside the module directory.
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// dirHasFiles reports whether dir exists and contains at least one regular
// file below it.
func dirHasFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.Type().IsRegular() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// replaceDir replaces dst with src. The old directory is moved aside first, so
// a failed rename can be rolled back instead of losing a working install.
func replaceDir(src, dst string) error {
	backup := dst + ".old"
	_ = os.RemoveAll(backup)
	hadOld := false
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, backup); err != nil {
			return err
		}
		hadOld = true
	}
	if err := os.Rename(src, dst); err != nil {
		if hadOld {
			_ = os.Rename(backup, dst)
		}
		return err
	}
	_ = os.RemoveAll(backup)
	return nil
}

// binaryName is the release asset name for a platform.
func binaryName(goos, goarch string) string {
	if a, ok := releaseAssets[goos+"/"+goarch]; ok {
		return a.name
	}
	return "opengrep"
}

// binaryFileName is the installed executable's name.
func binaryFileName(goos string) string {
	if goos == "windows" {
		return "opengrep.exe"
	}
	return "opengrep"
}

// supportedPlatforms lists the pinned platforms for an error message.
func supportedPlatforms() string {
	keys := make([]string, 0, len(releaseAssets))
	for key := range releaseAssets {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// requireHTTPS rejects a non-HTTPS URL, so an injected base URL cannot
// downgrade a module download.
func requireHTTPS(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse %q: %w", rawURL, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS download URL %q", rawURL)
	}
	return nil
}

// settingsFile is the stored opt-in setting. A missing or unreadable file means
// off: the setting fails closed, so a damaged file never starts a download.
type settingsFile struct {
	Enabled bool `json:"enabled"`
}

func (s *Service) readSetting() bool {
	if s.dataDir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, settingsFileName))
	if err != nil {
		return false
	}
	var stored settingsFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return false
	}
	return stored.Enabled
}

// writeFileAtomic writes data through a temporary file in the same directory
// and renames it into place, so a reader never sees half a document.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
