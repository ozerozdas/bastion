// Package depsdev implements bastion's opt-in outdated-package lookup (#38).
//
// It is an enrichment, not a Scanner: it does not read the workspace. It takes
// the package inventory another scanner (Trivy) already extracted and asks
// deps.dev for each package's default (latest) version. A package whose
// inventory version is strictly older becomes an `outdated` finding.
//
// The lookup is opt-in and off by default: with the setting off no request is
// made. Only the ecosystem and package name are sent; versions are compared
// locally. Every failure degrades to a scanner-run warning: it never fails a
// scan and never discards another scanner's findings.
package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/mod/semver"

	"github.com/ozerozdas/bastion/internal/findings"
)

const (
	// Name is the stable scanner id stored in scanner_runs.
	Name = "deps.dev"
	// Version identifies the API surface this lookup speaks; it is stored as
	// the scanner_version of the deps.dev run.
	Version = "v3"

	// DefaultBaseURL is the public deps.dev API.
	DefaultBaseURL = "https://api.deps.dev"

	settingsFileName = "outdated-settings.json"

	// cacheTTL is how long a package's default version is reused in memory.
	// deps.dev publishes releases continuously, so a day keeps repeated scans
	// from re-asking without showing a stale answer for long.
	cacheTTL = 24 * time.Hour
	// requestTimeout bounds one package lookup.
	requestTimeout = 10 * time.Second
	// scanBudget bounds one scan's lookups across every package.
	scanBudget = 30 * time.Second
	// workers bounds concurrent deps.dev requests.
	workers = 8
	// maxResponseBytes caps one response body. A package's version list is
	// small; a pathological response is rejected rather than decoded.
	maxResponseBytes = 4 << 20
	// maxVersionLength keeps a hostile response from storing an unbounded
	// string as a finding title or fixed version.
	maxVersionLength = 256
)

// Status is the read-only view the API and the CLI render.
type Status struct {
	// Enabled is the stored opt-in setting.
	Enabled bool
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir holds the opt-in setting. It is the directory the EPSS feed and
	// the other opt-in modules also store their consent in.
	DataDir string
	// BaseURL overrides the API location; tests point it at httptest.
	BaseURL string
	// HTTPClient lets tests count requests. Its timeout is replaced.
	HTTPClient *http.Client
	// Version is the build version for the User-Agent header.
	Version string
	// Now is the clock; tests use a fake to exercise the cache TTL.
	Now func() time.Time
	// Logger receives debug records for an unreadable setting.
	Logger *slog.Logger
}

// Service performs and caches the lookups and stores the opt-in setting. It is
// safe for concurrent use.
type Service struct {
	dataDir string
	baseURL string
	client  *http.Client
	agent   string
	now     func() time.Time
	log     *slog.Logger

	// enabled mirrors the stored setting. Match reads it per scan, so it must
	// not touch the filesystem.
	enabled atomic.Bool

	// cacheMu guards cache. Entries are the package's default version, empty
	// when deps.dev knows the package but marks no default version.
	cacheMu sync.Mutex
	cache   map[cacheKey]cacheEntry
}

type cacheKey struct {
	system string
	name   string
}

type cacheEntry struct {
	latest  string
	fetched time.Time
}

// target is one de-duplicated package lookup.
type target struct {
	system string
	name   string
}

// New wires a Service with production defaults for the unset seams. It reads
// the stored setting and performs no network call.
func New(cfg Config) *Service {
	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	client.Timeout = requestTimeout

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	agent := "bastion"
	if cfg.Version != "" {
		agent = "bastion/" + cfg.Version
	}

	s := &Service{
		dataDir: cfg.DataDir,
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
		agent:   agent,
		now:     now,
		log:     logger,
		cache:   make(map[cacheKey]cacheEntry),
	}
	s.enabled.Store(s.readSetting())
	return s
}

// Name is the stable scanner id stored in scanner_runs.
func (*Service) Name() string { return Name }

// Version is the deps.dev API surface the lookup speaks.
func (*Service) Version() string { return Version }

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
		return errors.New("deps.dev: data directory is required")
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("deps.dev: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("deps.dev: encode settings: %w", err)
	}
	path := filepath.Join(s.dataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("deps.dev: store settings: %w", err)
	}
	s.enabled.Store(enabled)
	return nil
}

// Snapshot reports the stored setting without any network call.
func (s *Service) Snapshot() Status {
	if s == nil {
		return Status{}
	}
	return Status{Enabled: s.enabled.Load()}
}

// Match looks up the default version of every supported package in the
// inventory and returns one outdated finding per package entry that is older.
// Warnings describe partial coverage (failed or skipped lookups); they never
// fail the scan. An error is returned only when the scan was canceled.
func (s *Service) Match(ctx context.Context, inventory []findings.Package, asset findings.Asset) ([]findings.Finding, []string, error) {
	if s == nil || !s.Enabled() {
		return nil, nil, nil
	}

	targets := lookups(inventory)
	if len(targets) == 0 {
		return nil, nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, scanBudget)
	defer cancel()

	var (
		mu       sync.Mutex
		latest   = make(map[cacheKey]string, len(targets))
		checked  atomic.Int32
		failures atomic.Int32
	)
	jobs := make(chan target)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					continue
				}
				version, err := s.latestVersion(ctx, t)
				if err != nil {
					failures.Add(1)
					continue
				}
				checked.Add(1)
				if version == "" {
					continue
				}
				mu.Lock()
				latest[cacheKey(t)] = version
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	warnings := make([]string, 0, 2)
	if failed := failures.Load(); failed > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"deps.dev: %d of %d package lookups failed", failed, len(targets)))
	}
	if unattempted := len(targets) - int(checked.Load()) - int(failures.Load()); unattempted > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"deps.dev: %d of %d package lookups skipped (time budget)", unattempted, len(targets)))
	}

	return s.findings(inventory, latest, asset), warnings, nil
}

// findings expands the lookups into one outdated finding per inventory entry.
// Entries are de-duplicated by ecosystem, name, version and location, so the
// same package listed in two manifests yields two findings but one lookup.
func (s *Service) findings(inventory []findings.Package, latest map[cacheKey]string, asset findings.Asset) []findings.Finding {
	seen := make(map[inventoryKey]struct{}, len(inventory))
	out := make([]findings.Finding, 0)

	for _, p := range inventory {
		system, ok := systems[strings.ToLower(p.Ecosystem)]
		if !ok || p.Name == "" || p.Version == "" {
			continue
		}
		key := inventoryKey{
			ecosystem: strings.ToLower(p.Ecosystem),
			name:      p.Name,
			version:   p.Version,
			location:  p.Path,
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		newest, ok := latest[cacheKey{system: system, name: p.Name}]
		if !ok || newest == "" {
			continue
		}
		order, ok := compareVersions(p.Version, newest)
		if !ok || order >= 0 {
			continue
		}

		severity := findings.SeverityLow
		if majorBehind(p.Version, newest) {
			// A major-version gap is more than routine drift: the upgrade may
			// need migration work, so it is reported as medium. Everything
			// else is low.
			severity = findings.SeverityMedium
		}

		f := findings.Finding{
			AssetID:        asset.ID,
			Type:           findings.TypeOutdated,
			RuleID:         ruleID,
			Severity:       severity,
			Title:          fmt.Sprintf("%s %s → %s", p.Name, p.Version, newest),
			PackageName:    p.Name,
			PackageVersion: p.Version,
			FixedVersion:   newest,
			Ecosystem:      p.Ecosystem,
			Location:       p.Path,
			Description:    fmt.Sprintf("deps.dev reports %s as the latest version of %s; this project uses %s.", newest, p.Name, p.Version),
			Scanner:        Name,
		}
		f.Fingerprint = findings.Fingerprint(asset.ID, f)
		out = append(out, f)
	}

	findings.SortFindings(out)
	return out
}

// ruleID is constant: the package, current version and location in the
// fingerprint already identify the finding.
const ruleID = "outdated"

// inventoryKey de-duplicates one inventory entry.
type inventoryKey struct {
	ecosystem string
	name      string
	version   string
	location  string
}

// systems maps Trivy's ecosystem names onto deps.dev's systems. Ecosystems
// deps.dev does not serve (OS packages, Composer, Hex and so on) are skipped.
var systems = map[string]string{
	"go":    "GO",
	"npm":   "NPM",
	"cargo": "CARGO",
	"maven": "MAVEN",
	"pypi":  "PYPI",
	"nuget": "NUGET",
	"gem":   "RUBYGEMS",
}

// lookups deduplicates the inventory into one lookup per package. Order follows
// the inventory so results and warnings are stable.
func lookups(inventory []findings.Package) []target {
	seen := make(map[cacheKey]struct{}, len(inventory))
	out := make([]target, 0, len(inventory))
	for _, p := range inventory {
		system, ok := systems[strings.ToLower(p.Ecosystem)]
		if !ok || p.Name == "" || p.Version == "" {
			continue
		}
		key := cacheKey{system: system, name: p.Name}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, target{system: system, name: p.Name})
	}
	return out
}

// latestVersion returns a package's default version, from the cache when it is
// fresh. An empty version with a nil error means deps.dev has no default for
// the package; that is not a failure.
func (s *Service) latestVersion(ctx context.Context, t target) (string, error) {
	key := cacheKey(t)
	if version, ok := s.cached(key); ok {
		return version, nil
	}
	version, err := s.fetch(ctx, t)
	if err != nil {
		return "", err
	}
	s.store(key, version)
	return version, nil
}

func (s *Service) cached(key cacheKey) (string, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	entry, ok := s.cache[key]
	if !ok {
		return "", false
	}
	if s.now().Sub(entry.fetched) >= cacheTTL {
		delete(s.cache, key)
		return "", false
	}
	return entry.latest, true
}

func (s *Service) store(key cacheKey, latest string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache[key] = cacheEntry{latest: latest, fetched: s.now()}
}

// fetch asks deps.dev for one package's versions and returns its default. A
// 404 means deps.dev does not know the package, which is not an error.
func (s *Service) fetch(ctx context.Context, t target) (string, error) {
	endpoint := s.baseURL + "/v3/systems/" + url.PathEscape(t.system) + "/packages/" + url.PathEscape(t.name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("deps.dev: build request: %w", err)
	}
	req.Header.Set("User-Agent", s.agent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("deps.dev: request %s: %w", t.name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("deps.dev: request %s: status %d", t.name, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("deps.dev: read %s response: %w", t.name, err)
	}
	if len(data) > maxResponseBytes {
		return "", fmt.Errorf("deps.dev: %s response exceeds %d bytes", t.name, maxResponseBytes)
	}

	var payload packageResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("deps.dev: decode %s response: %w", t.name, err)
	}
	for _, v := range payload.Versions {
		if !v.IsDefault {
			continue
		}
		version := strings.TrimSpace(v.VersionKey.Version)
		if !validVersion(version) {
			return "", fmt.Errorf("deps.dev: %s returned an unusable default version", t.name)
		}
		return version, nil
	}
	return "", nil
}

// validVersion accepts only a bounded, control-free string. The response is
// untrusted input that ends up in finding titles and the database.
func validVersion(version string) bool {
	if version == "" || len(version) > maxVersionLength {
		return false
	}
	if strings.ContainsFunc(version, unicode.IsControl) {
		return false
	}
	return true
}

// compareVersions orders two versions with a minimal semver comparison. exact
// is false when either value is not readable as semver; such a pair produces no
// finding rather than a guessed upgrade. The ecosystem parsers in
// internal/fixplan are not exported, and reusing them here would couple the
// enrichment to the fix-plan package for a single comparison.
func compareVersions(current, latest string) (order int, exact bool) {
	a, ok := semverVersion(current)
	if !ok {
		return 0, false
	}
	b, ok := semverVersion(latest)
	if !ok {
		return 0, false
	}
	return semver.Compare(a, b), true
}

// semverVersion normalizes a version into the "v"-prefixed semver form
// golang.org/x/mod/semver expects. Missing minor and patch components are
// padded, which covers the common "1.2" and "1" registry versions.
func semverVersion(version string) (string, bool) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return "", false
	}
	for _, candidate := range []string{version, version + ".0", version + ".0.0"} {
		if semver.IsValid("v" + candidate) {
			return "v" + candidate, true
		}
	}
	return "", false
}

// majorBehind reports whether latest is on a newer major version than current.
func majorBehind(current, latest string) bool {
	a, ok := semverVersion(current)
	if !ok {
		return false
	}
	b, ok := semverVersion(latest)
	if !ok {
		return false
	}
	return semver.Compare(semver.Major(a), semver.Major(b)) < 0
}

// settingsFile is the stored opt-in setting. A missing or unreadable file means
// off: the lookup fails closed, so a damaged file never enables a request.
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
	var file settingsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return false
	}
	return file.Enabled
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

// The types below mirror only the deps.dev API fields the lookup consumes.

type packageResponse struct {
	Versions []packageVersion `json:"versions"`
}

type packageVersion struct {
	VersionKey versionKey `json:"versionKey"`
	IsDefault  bool       `json:"isDefault"`
}

type versionKey struct {
	Version string `json:"version"`
}
