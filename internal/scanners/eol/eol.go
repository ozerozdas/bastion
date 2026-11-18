// Package eol implements bastion's opt-in end-of-life lookup (#55).
//
// It is an enrichment, not a Scanner: it takes the operating system and the
// package inventory Trivy already extracted and asks endoflife.date for the
// release cycles of those products. A release past its end of life becomes one
// `outdated` finding that names the date.
//
// The lookup is off by default: with the setting off no request is made. Only
// the product name is sent; versions are compared locally. Every failure
// degrades to a scanner-run warning and never fails a scan.
package eol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/ozerozdas/bastion/internal/findings"
)

const (
	// Name is the stable scanner id stored in scanner_runs.
	Name = "endoflife.date"
	// Version identifies the API surface this lookup speaks.
	Version = "v1"
	// DefaultBaseURL is the public endoflife.date API.
	DefaultBaseURL = "https://endoflife.date"

	settingsFileName = "eol-settings.json"
	ruleID           = "eol"

	// cacheTTL is how long a product's release cycles are reused in memory.
	cacheTTL = 24 * time.Hour
	// requestTimeout bounds one product lookup.
	requestTimeout = 10 * time.Second
	// maxResponseBytes caps one response body; a product's cycles are small.
	maxResponseBytes = 4 << 20
	// maxNameLength bounds a release name taken from the untrusted response.
	maxNameLength = 64
)

// product is one endoflife.date product and the label findings show for it.
type product struct {
	slug  string
	label string
}

// osProducts maps Trivy's OS family names onto endoflife.date products.
var osProducts = map[string]product{
	"alpine":        {"alpine-linux", "Alpine Linux"},
	"alma":          {"almalinux", "AlmaLinux"},
	"amazon":        {"amazon-linux", "Amazon Linux"},
	"centos":        {"centos", "CentOS"},
	"debian":        {"debian", "Debian"},
	"fedora":        {"fedora", "Fedora"},
	"opensuse-leap": {"opensuse", "openSUSE Leap"},
	"opensuse.leap": {"opensuse", "openSUSE Leap"},
	"oracle":        {"oracle-linux", "Oracle Linux"},
	"redhat":        {"rhel", "Red Hat Enterprise Linux"},
	"rocky":         {"rocky-linux", "Rocky Linux"},
	"sles":          {"sles", "SUSE Linux Enterprise Server"},
	"ubuntu":        {"ubuntu", "Ubuntu"},
}

// goProduct is the one runtime detected from the inventory.
//
// ponytail: only Go's stdlib is checked. A distro-packaged runtime (python3,
// nodejs) keeps receiving distro patches after its upstream end of life, so
// flagging it would be a false alarm; the OS finding already covers it.
var goProduct = product{"go", "Go"}

// Status is the read-only view the API renders.
type Status struct {
	Enabled bool
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir holds the opt-in setting.
	DataDir string
	// BaseURL overrides the API location; tests point it at httptest.
	BaseURL string
	// Version is the build version for the User-Agent header.
	Version string
	// Now is the clock; tests use a fake to exercise the cache TTL.
	Now func() time.Time
}

// Service performs and caches the lookups and stores the opt-in setting. It is
// safe for concurrent use.
type Service struct {
	dataDir string
	baseURL string
	client  *http.Client
	agent   string
	now     func() time.Time
	enabled atomic.Bool

	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	releases []release
	fetched  time.Time
}

// New wires a Service. It reads the stored setting and makes no network call.
func New(cfg Config) *Service {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	agent := "bastion"
	if cfg.Version != "" {
		agent = "bastion/" + cfg.Version
	}
	s := &Service{
		dataDir: cfg.DataDir,
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: requestTimeout},
		agent:   agent,
		now:     now,
		cache:   make(map[string]cacheEntry),
	}
	s.enabled.Store(s.readSetting())
	return s
}

// Name is the stable scanner id stored in scanner_runs.
func (*Service) Name() string { return Name }

// Version is the API surface the lookup speaks.
func (*Service) Version() string { return Version }

// Enabled reports the stored setting. It never touches the network.
func (s *Service) Enabled() bool { return s != nil && s.enabled.Load() }

// Snapshot reports the stored setting without any network call.
func (s *Service) Snapshot() Status { return Status{Enabled: s.Enabled()} }

// SetEnabled stores the user's answer. It affects the next scan.
func (s *Service) SetEnabled(enabled bool) error {
	if s.dataDir == "" {
		return errors.New("eol: data directory is required")
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("eol: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("eol: encode settings: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(s.dataDir, settingsFileName), append(data, '\n')); err != nil {
		return fmt.Errorf("eol: store settings: %w", err)
	}
	s.enabled.Store(enabled)
	return nil
}

// subject is one installed product to check.
type subject struct {
	product   product
	ecosystem string
	name      string
	version   string
}

// Match returns one outdated finding per end-of-life OS or runtime release.
// osFamily and osName come from the scanner and are empty for a target without
// an OS. Warnings describe failed lookups; an error means the scan was canceled.
func (s *Service) Match(ctx context.Context, osFamily, osName string, inventory []findings.Package, asset findings.Asset) ([]findings.Finding, []string, error) {
	if !s.Enabled() {
		return nil, nil, nil
	}

	out := make([]findings.Finding, 0)
	var warnings []string
	for _, sub := range subjects(osFamily, osName, inventory) {
		releases, err := s.releases(ctx, sub.product.slug)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		if f, ok := finding(sub, releases, asset); ok {
			out = append(out, f)
		}
	}
	findings.SortFindings(out)
	return out, warnings, nil
}

// subjects lists the OS and each distinct Go release in the inventory. Go
// binaries built with the same release collapse into one subject.
func subjects(osFamily, osName string, inventory []findings.Package) []subject {
	var out []subject
	family := strings.ToLower(strings.TrimSpace(osFamily))
	// Trivy can append a codename: "2 (Karoo)".
	if fields := strings.Fields(osName); len(fields) > 0 {
		if p, ok := osProducts[family]; ok {
			out = append(out, subject{product: p, ecosystem: "os", name: family, version: fields[0]})
		}
	}
	seen := make(map[string]struct{})
	for _, p := range inventory {
		if p.Name != "stdlib" || !strings.EqualFold(p.Ecosystem, "go") {
			continue
		}
		version := strings.TrimPrefix(strings.TrimSpace(p.Version), "v")
		if _, dup := seen[version]; dup || version == "" {
			continue
		}
		seen[version] = struct{}{}
		out = append(out, subject{product: goProduct, ecosystem: "go", name: "go", version: version})
	}
	return out
}

// finding builds the finding for a subject whose release cycle has ended.
func finding(sub subject, releases []release, asset findings.Asset) (findings.Finding, bool) {
	cycle, ok := matchCycle(sub.version, releases)
	if !ok || !cycle.IsEOL {
		return findings.Finding{}, false
	}

	title := fmt.Sprintf("%s %s has reached end of life", sub.product.label, cycle.Name)
	description := fmt.Sprintf("%s %s no longer receives security updates.", sub.product.label, cycle.Name)
	if date := cycle.eolDate(); date != "" {
		title = fmt.Sprintf("%s %s reached end of life on %s", sub.product.label, cycle.Name, date)
		description = fmt.Sprintf("%s %s stopped receiving security updates on %s.", sub.product.label, cycle.Name, date)
	}

	f := findings.Finding{
		AssetID:        asset.ID,
		Type:           findings.TypeOutdated,
		RuleID:         ruleID,
		Severity:       findings.SeverityHigh,
		Title:          title,
		PackageName:    sub.name,
		PackageVersion: sub.version,
		FixedVersion:   newestSupported(releases),
		Ecosystem:      sub.ecosystem,
		Description:    description,
		Scanner:        Name,
	}
	f.Fingerprint = findings.Fingerprint(asset.ID, f)
	return f, true
}

// matchCycle finds the longest release name that is a dotted prefix of version,
// so 3.18.4 matches 3.18 and never 3.1.
func matchCycle(version string, releases []release) (release, bool) {
	var best release
	for _, r := range releases {
		if (version == r.Name || strings.HasPrefix(version, r.Name+".")) && len(r.Name) > len(best.Name) {
			best = r
		}
	}
	return best, best.Name != ""
}

// newestSupported returns the first release still maintained; endoflife.date
// lists the newest cycle first.
func newestSupported(releases []release) string {
	for _, r := range releases {
		if !r.IsEOL {
			return r.Name
		}
	}
	return ""
}

// releases returns a product's cycles, from the cache when fresh.
func (s *Service) releases(ctx context.Context, slug string) ([]release, error) {
	s.cacheMu.Lock()
	entry, ok := s.cache[slug]
	s.cacheMu.Unlock()
	if ok && s.now().Sub(entry.fetched) < cacheTTL {
		return entry.releases, nil
	}

	releases, err := s.fetch(ctx, slug)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	s.cache[slug] = cacheEntry{releases: releases, fetched: s.now()}
	s.cacheMu.Unlock()
	return releases, nil
}

// fetch downloads one product. Its response is untrusted: names that could not
// be a release are dropped before they can reach a finding.
func (s *Service) fetch(ctx context.Context, slug string) ([]release, error) {
	endpoint := s.baseURL + "/api/v1/products/" + url.PathEscape(slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("eol: build %s request: %w", slug, err)
	}
	req.Header.Set("User-Agent", s.agent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eol: request %s: %w", slug, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eol: request %s: status %d", slug, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("eol: read %s response: %w", slug, err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("eol: %s response exceeds %d bytes", slug, maxResponseBytes)
	}
	var payload productResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("eol: decode %s response: %w", slug, err)
	}

	releases := make([]release, 0, len(payload.Result.Releases))
	for _, r := range payload.Result.Releases {
		if validName(r.Name) {
			releases = append(releases, r)
		}
	}
	return releases, nil
}

func validName(name string) bool {
	return name != "" && len(name) <= maxNameLength && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	})
}

// settingsFile is the stored opt-in. A missing or damaged file means off.
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
	return json.Unmarshal(data, &file) == nil && file.Enabled
}

// writeFileAtomic renames a finished temporary file into place.
func writeFileAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// The types below mirror only the API fields the lookup consumes.

type productResponse struct {
	Result struct {
		Releases []release `json:"releases"`
	} `json:"result"`
}

type release struct {
	Name    string  `json:"name"`
	IsEOL   bool    `json:"isEol"`
	EOLFrom *string `json:"eolFrom"`
}

// eolDate returns the end-of-life date, or "" when absent or malformed.
func (r release) eolDate() string {
	if r.EOLFrom == nil {
		return ""
	}
	date, err := time.Parse(time.DateOnly, *r.EOLFrom)
	if err != nil {
		return ""
	}
	return date.Format(time.DateOnly)
}
