// Package update implements bastion's opt-in release check (ADR-006).
//
// The check never runs unless the user turned it on in the UI: consent is a
// small file in the data directory, and unset or off means no request at all.
// A successful or failed check is cached in the cache directory for 24 hours,
// so bastion contacts github.com at most once a day, and failures are silent
// (debug log only).
//
// The package keeps every side effect behind a seam (HTTP client, clock,
// environment, executable) so tests never touch the network.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Consent is the user's answer to "check for new releases?".
type Consent string

const (
	// ConsentUnset means the user has not answered yet. No request is made.
	ConsentUnset Consent = "unset"
	// ConsentOn means the user opted in.
	ConsentOn Consent = "on"
	// ConsentOff means the user declined. No request is made.
	ConsentOff Consent = "off"
)

const (
	// EnvNoUpdateCheck always disables the check, whatever the stored consent.
	EnvNoUpdateCheck = "BASTION_NO_UPDATE_CHECK"

	// checkInterval is the minimum time between two outbound requests.
	checkInterval = 24 * time.Hour
	// requestTimeout bounds one request; the check never blocks startup or a
	// scan for longer than this.
	requestTimeout = 5 * time.Second

	consentFileName = "update-consent.json"
	cacheFileName   = "update-check.json"

	releasesLatestPath = "/ozerozdas/bastion/releases/latest"
	releasesTagBase    = "https://github.com/ozerozdas/bastion/releases/tag/"
)

// Status is the read-only view the API and the CLI render.
type Status struct {
	Current         string
	Latest          string
	UpdateAvailable bool
	Consent         Consent
	// Command is the install-method-specific update command; empty on Windows.
	Command string
	// ReleaseURL is the release-notes page for Latest.
	ReleaseURL string
	// CheckedAt is when the cached result was written; zero when never checked.
	CheckedAt time.Time
	// Disabled explains why no check can run (an environment switch, CI or a
	// dev build). It is empty when the check is allowed.
	Disabled string
}

// Config configures a Checker. Every zero value has a production default, so
// callers normally set only the first three fields.
type Config struct {
	CurrentVersion string
	DataDir        string
	CacheDir       string

	// BaseURL overrides https://github.com (tests point it at httptest).
	BaseURL string
	// HTTPClient lets tests count requests. CheckRedirect and Timeout are
	// always replaced by this package.
	HTTPClient *http.Client
	// Now is the clock; tests use a fake to exercise cache expiry.
	Now func() time.Time
	// Getenv is the environment; tests stub it.
	Getenv func(string) string
	// Executable resolves the running binary, for the install hint.
	Executable func() (string, error)
	// GOOS selects the install hint.
	GOOS string
	// Logger receives the debug record a failed check writes.
	Logger *slog.Logger
	// Spawn runs the background check. It defaults to `go f()`; tests set it
	// to run inline, so an assertion after Status() sees any work it started.
	Spawn func(func())
}

// Checker performs and caches the release check. It is safe for concurrent use.
type Checker struct {
	current    string
	dataDir    string
	cacheDir   string
	baseURL    string
	client     *http.Client
	now        func() time.Time
	getenv     func(string) string
	executable func() (string, error)
	goos       string
	log        *slog.Logger
	spawn      func(func())

	// mu serialises checks, so two concurrent UI requests cannot both spend
	// the daily budget.
	mu sync.Mutex

	// lastAttempt is when the last outbound request was started. It is part of
	// the 24-hour budget even when writing the cache fails, so an unwritable
	// cache directory cannot turn into one request per call. Atomic because
	// Status reads it without taking mu (it must never block on a check).
	lastAttempt atomic.Int64
	// inFlight is the single-flight guard for background checks: only the
	// caller that flips false to true spawns the check.
	inFlight atomic.Bool
}

// New wires a Checker with production defaults for the unset seams.
func New(cfg Config) *Checker {
	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		// The Location header carries the tag; following the redirect would
		// download a page for no benefit.
		return http.ErrUseLastResponse
	}
	client.Timeout = requestTimeout

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://github.com"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	executable := cfg.Executable
	if executable == nil {
		executable = os.Executable
	}
	goos := cfg.GOOS
	if goos == "" {
		goos = defaultGOOS
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	spawn := cfg.Spawn
	if spawn == nil {
		spawn = func(f func()) { go f() }
	}

	return &Checker{
		current:    cfg.CurrentVersion,
		dataDir:    cfg.DataDir,
		cacheDir:   cfg.CacheDir,
		baseURL:    strings.TrimRight(baseURL, "/"),
		client:     client,
		now:        now,
		getenv:     getenv,
		executable: executable,
		goos:       goos,
		log:        logger,
		spawn:      spawn,
	}
}

// Consent reads the stored answer. A missing, unreadable or unknown file means
// unset: consent fails closed, so a damaged file never enables a request.
func (c *Checker) Consent() Consent {
	data, err := os.ReadFile(filepath.Join(c.dataDir, consentFileName))
	if err != nil {
		return ConsentUnset
	}
	var stored consentFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return ConsentUnset
	}
	switch stored.Consent {
	case ConsentOn:
		return ConsentOn
	case ConsentOff:
		return ConsentOff
	default:
		return ConsentUnset
	}
}

// SetConsent stores the user's answer. Only the UI calls this; the CLI only
// reads.
func (c *Checker) SetConsent(enabled bool) error {
	consent := ConsentOff
	if enabled {
		consent = ConsentOn
	}
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	return writeJSON(filepath.Join(c.dataDir, consentFileName), consentFile{Consent: consent})
}

// Snapshot reads consent and the cached result without any network call.
func (c *Checker) Snapshot() Status {
	status := Status{
		Current:  c.current,
		Consent:  c.Consent(),
		Disabled: c.disabledReason(),
	}

	entry, ok := c.readCache()
	if !ok {
		return status
	}
	status.CheckedAt = entry.CheckedAt
	status.Latest = entry.Latest
	if entry.Latest != "" && newerThan(c.current, entry.Latest) {
		status.UpdateAvailable = true
		status.Command = c.installCommand()
		status.ReleaseURL = releasesTagBase + entry.Latest
	}
	return status
}

// Status returns the cached view and starts one background check when consent
// is on and the cache is older than 24 hours. It never waits for the network,
// so API handlers and `bastion serve` stay fast. Concurrent stale calls share
// the single in-flight check.
func (c *Checker) Status() Status {
	status := c.Snapshot()
	if status.Consent != ConsentOn || status.Disabled != "" || !c.due() {
		return status
	}
	// Only the caller that flips false to true spawns a check, so a burst of
	// page loads cannot start a burst of requests.
	if !c.inFlight.CompareAndSwap(false, true) {
		return status
	}
	// The request context belongs to the handler and is canceled when it
	// returns, so the background check gets its own bounded context.
	c.spawn(func() {
		defer c.inFlight.Store(false)
		_ = c.CheckNow(context.Background())
	})
	return status
}

// CheckNow performs a check when consent is on, the environment allows it and
// the cache is due. It returns the refreshed status. Network and cache failures
// are logged at debug level and never returned: a release check must not
// produce user-visible errors.
func (c *Checker) CheckNow(ctx context.Context) Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	status := c.Snapshot()
	if status.Consent != ConsentOn || status.Disabled != "" || !c.due() {
		return status
	}

	checkedAt := c.now()
	// Record the attempt before the request: if the cache write fails, the
	// daily budget still holds.
	c.lastAttempt.Store(checkedAt.UnixNano())
	latest, err := c.fetchLatest(ctx)
	if err != nil {
		// Debug only: the next check is a day away, and a failed release check
		// is not something the user can act on.
		c.log.Debug("update check failed", "error", err)
	}

	// A failed check is cached too, so a transient outage cannot turn into one
	// request per page load.
	if err := c.writeCache(cacheEntry{CheckedAt: checkedAt, Latest: latest}); err != nil {
		c.log.Debug("store update check result", "error", err)
	}
	return c.Snapshot()
}

// fetchLatest asks github.com for the latest release and reads the tag from the
// redirect's Location header. The response body is never read.
func (c *Checker) fetchLatest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+releasesLatestPath, nil)
	if err != nil {
		return "", fmt.Errorf("build release request: %w", err)
	}
	req.Header.Set("User-Agent", "bastion/"+c.current)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusMultipleChoices || resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("latest release answered %d, expected a redirect", resp.StatusCode)
	}
	tag, ok := tagFromLocation(resp.Header.Get("Location"))
	if !ok {
		return "", fmt.Errorf("latest release redirected without a usable tag")
	}
	return tag, nil
}

// disabledReason returns a non-empty explanation when the check must never run,
// regardless of the stored consent.
func (c *Checker) disabledReason() string {
	if c.getenv(EnvNoUpdateCheck) == "1" {
		return EnvNoUpdateCheck + "=1"
	}
	if c.getenv("CI") != "" {
		return "CI environment"
	}
	if !isReleaseVersion(c.current) {
		return "dev build"
	}
	return ""
}

// installCommand resolves the running binary and maps it onto an update
// command. A broken executable path still gets the generic hint.
func (c *Checker) installCommand() string {
	path := ""
	if exe, err := c.executable(); err == nil {
		path = exe
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			path = resolved
		}
	}
	return installCommandFor(path, c.goos)
}

// cacheEntry is the cached result of one check. Latest is empty when the check
// failed, but CheckedAt is still set so the 24-hour budget applies.
type cacheEntry struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest,omitempty"`
}

// consentFile is the on-disk consent document.
type consentFile struct {
	Consent Consent `json:"consent"`
}

// readCache returns the cached entry when the file exists and decodes. An
// entry whose latest tag is not a valid semver tag is ignored, so a damaged or
// hand-edited file cannot make Snapshot compare nonsense.
func (c *Checker) readCache() (cacheEntry, bool) {
	data, err := os.ReadFile(filepath.Join(c.cacheDir, cacheFileName))
	if err != nil {
		return cacheEntry{}, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return cacheEntry{}, false
	}
	if entry.CheckedAt.IsZero() {
		return cacheEntry{}, false
	}
	if entry.Latest != "" && !validVersion(entry.Latest) {
		return cacheEntry{}, false
	}
	return entry, true
}

// writeCache stores the result atomically, so a reader never sees half a file.
func (c *Checker) writeCache(entry cacheEntry) error {
	if err := os.MkdirAll(c.cacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	return writeJSON(filepath.Join(c.cacheDir, cacheFileName), entry)
}

// due reports whether the daily budget allows another request. The cache's
// checked_at and the in-memory last attempt both count, so a failed cache write
// cannot bypass the budget.
func (c *Checker) due() bool {
	var last time.Time
	if entry, ok := c.readCache(); ok {
		last = entry.CheckedAt
	}
	if nanos := c.lastAttempt.Load(); nanos != 0 {
		if attempt := time.Unix(0, nanos); attempt.After(last) {
			last = attempt
		}
	}
	if last.IsZero() {
		return true
	}
	return c.now().Sub(last) >= checkInterval
}

// writeJSON writes data with owner-only permissions through a temporary file
// in the same directory, then renames it into place.
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

// tagFromLocation extracts the release tag from a GitHub releases/tag URL.
func tagFromLocation(location string) (string, bool) {
	if location == "" {
		return "", false
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	const marker = "/releases/tag/"
	index := strings.Index(parsed.Path, marker)
	if index < 0 {
		return "", false
	}
	tag := strings.TrimSuffix(parsed.Path[index+len(marker):], "/")
	if tag == "" || strings.Contains(tag, "/") {
		return "", false
	}
	if !validVersion(tag) {
		return "", false
	}
	return tag, true
}
