// Package osv matches an existing package inventory against the OSV database.
//
// It is not a Scanner: it does not read the workspace. It takes the packages
// another scanner (Trivy) already extracted, queries OSV's batch API for
// advisories affecting them, and turns them into findings: MAL- advisories
// become malware findings, everything else a vulnerability finding. The scan
// pipeline merges advisories Trivy already reported by their alias sets.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
)

const (
	// DefaultBaseURL is the public OSV API.
	DefaultBaseURL = "https://api.osv.dev"
	// Version identifies the API surface this matcher speaks; it is stored as
	// the scanner_version of the osv run.
	Version = "api/v1"

	// maxBatchSize is OSV's documented limit for POST /v1/querybatch.
	maxBatchSize = 1000
	// maxDetailLookups bounds the number of advisory detail requests one scan
	// makes. Ids beyond the bound still produce findings, without a summary,
	// severity or aliases. 500 covers a normal application's advisory count
	// while keeping a pathological inventory from hammering the API.
	maxDetailLookups = 500
	// detailWorkers bounds concurrent advisory detail requests.
	detailWorkers = 8
	// maxPaginationRounds bounds page_token follow-ups for one batch. A
	// response that still carries tokens after this many rounds is truncated
	// with a warning rather than followed forever.
	maxPaginationRounds = 10
	// requestTimeout bounds one HTTP request. A large inventory is queried in
	// several batches, each with its own budget.
	requestTimeout = 30 * time.Second
	// maxResponseBytes caps one response body.
	maxResponseBytes = 8 << 20

	// malwarePrefix marks OSV's malicious-package advisories.
	malwarePrefix = "MAL-"
)

// Matcher queries the OSV API. The zero value is not usable: call New.
type Matcher struct {
	BaseURL   string
	UserAgent string
	Client    *http.Client
}

// New returns a matcher that identifies itself as bastion/<version>.
func New(version string) *Matcher {
	if version == "" {
		version = "dev"
	}
	return &Matcher{
		BaseURL:   DefaultBaseURL,
		UserAgent: "bastion/" + version,
		Client:    &http.Client{Timeout: requestTimeout},
	}
}

// Name is the stable scanner id stored in scanner_runs.
func (*Matcher) Name() string { return "osv" }

// Version is the OSV API surface the matcher speaks.
func (*Matcher) Version() string { return Version }

// Match queries OSV for the packages in inventory and returns one finding per
// inventory entry and advisory. MAL- advisories become malware findings (always
// critical); the rest become vulnerability findings whose severity comes from
// the advisory. Packages without a version, or in an ecosystem OSV does not
// name, are skipped.
//
// A query failure is returned so the caller can record the run as failed; the
// scan itself must continue without these findings.
func (m *Matcher) Match(ctx context.Context, inventory []findings.Package, asset findings.Asset) ([]findings.Finding, error) {
	queries, keys := inventoryQueries(inventory)
	if len(queries) == 0 {
		return nil, nil
	}

	ids, err := m.query(ctx, queries, keys)
	if err != nil {
		return nil, err
	}

	details := m.lookupDetails(ctx, ids)
	return m.findings(asset, inventory, ids, details), nil
}

// query runs the batch queries and returns the advisory ids per inventory key.
// Each batch follows next_page_token up to maxPaginationRounds, re-issuing only
// the queries that returned a token.
func (m *Matcher) query(ctx context.Context, queries []query, keys []pkgKey) (map[pkgKey][]string, error) {
	ids := make(map[pkgKey][]string)
	for start := 0; start < len(queries); start += maxBatchSize {
		end := min(start+maxBatchSize, len(queries))
		pending := slices.Clone(queries[start:end])
		pendingKeys := slices.Clone(keys[start:end])

		for round := 0; ; round++ {
			var resp batchResponse
			if err := m.postBatch(ctx, pending, &resp); err != nil {
				return nil, err
			}
			if len(resp.Results) != len(pending) {
				// A short or long list would attach advisories to the wrong
				// package, so it is an error rather than a partial result.
				return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(pending))
			}

			next := make([]query, 0, len(pending))
			nextKeys := make([]pkgKey, 0, len(pending))
			for i, res := range resp.Results {
				key := pendingKeys[i]
				for _, v := range res.Vulns {
					if !slices.Contains(ids[key], v.ID) {
						ids[key] = append(ids[key], v.ID)
					}
				}
				slices.Sort(ids[key])

				if res.NextPageToken != "" {
					q := pending[i]
					q.PageToken = res.NextPageToken
					next = append(next, q)
					nextKeys = append(nextKeys, key)
				}
			}

			if len(next) == 0 {
				break
			}
			if round+1 >= maxPaginationRounds {
				slog.Warn("osv: querybatch pagination capped", "rounds", maxPaginationRounds, "pending", len(next))
				break
			}
			pending, pendingKeys = next, nextKeys
		}
	}
	return ids, nil
}

// postBatch sends one page of queries under its own timeout.
func (m *Matcher) postBatch(ctx context.Context, queries []query, out *batchResponse) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return m.do(ctx, http.MethodPost, "/v1/querybatch", batchRequest{Queries: queries}, out)
}

// lookupDetails fetches the summary, description, severity and aliases for the
// advisories, concurrently and best effort: a failed detail request falls back
// to the advisory id, and the finding is still emitted (for MAL- the id alone
// already proves the package is malicious). Failures are summarised in one log
// line.
func (m *Matcher) lookupDetails(ctx context.Context, ids map[pkgKey][]string) map[string]vulnerability {
	unique := make([]string, 0)
	for _, list := range ids {
		unique = append(unique, list...)
	}
	slices.Sort(unique)
	unique = slices.Compact(unique)

	if len(unique) > maxDetailLookups {
		slog.Warn("osv: advisory detail lookups capped", "wanted", len(unique), "cap", maxDetailLookups)
		unique = unique[:maxDetailLookups]
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failures atomic.Int32
		sem      = make(chan struct{}, detailWorkers)
	)
	details := make(map[string]vulnerability, len(unique))
	for _, id := range unique {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var v vulnerability
			if err := m.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
				failures.Add(1)
				return
			}
			mu.Lock()
			details[id] = v
			mu.Unlock()
		}()
	}
	wg.Wait()

	if failed := failures.Load(); failed > 0 {
		slog.Warn("osv: advisory details unavailable", "count", failed, "requested", len(unique))
	}
	return details
}

// findings expands the per-package advisory ids into findings.
func (m *Matcher) findings(asset findings.Asset, inventory []findings.Package, ids map[pkgKey][]string, details map[string]vulnerability) []findings.Finding {
	out := make([]findings.Finding, 0)
	for _, p := range inventory {
		for _, id := range ids[pkgKey{p.Ecosystem, p.Name, p.Version}] {
			detail := details[id]
			f := findings.Finding{
				AssetID:        asset.ID,
				RuleID:         id,
				Title:          detail.Summary,
				PackageName:    p.Name,
				PackageVersion: p.Version,
				Ecosystem:      p.Ecosystem,
				Location:       p.Path,
				Description:    detail.Details,
				Scanner:        m.Name(),
				Aliases:        detail.Aliases,
			}
			if strings.HasPrefix(id, malwarePrefix) {
				f.Type = findings.TypeMalware
				f.Severity = findings.SeverityCritical
				if f.Title == "" {
					f.Title = "Malicious package " + p.Name
				}
			} else {
				f.Type = findings.TypeVulnerability
				f.Severity = detailSeverity(detail)
				if f.Title == "" {
					// The advisory id is still a useful title, and the schema
					// requires one.
					f.Title = id
				}
			}
			f.Fingerprint = findings.Fingerprint(asset.ID, f)
			out = append(out, f)
		}
	}
	findings.SortFindings(out)
	return out
}

// detailSeverity maps OSV's database_specific severity onto the §5 scale.
// MODERATE is OSV's name for medium. A missing or unrecognised value is
// unknown rather than guessed.
func detailSeverity(v vulnerability) findings.Severity {
	switch strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return findings.SeverityCritical
	case "HIGH":
		return findings.SeverityHigh
	case "MODERATE", "MEDIUM":
		return findings.SeverityMedium
	case "LOW":
		return findings.SeverityLow
	default:
		return findings.SeverityUnknown
	}
}

// pkgKey identifies one version of one package in the inventory. The
// ecosystem is the Trivy-style name, so the key maps results back to the
// inventory entry that produced them.
type pkgKey struct {
	ecosystem string
	name      string
	version   string
}

// inventoryQueries deduplicates the inventory into OSV queries and returns the
// key each query answers. Order follows the inventory so results are stable.
func inventoryQueries(inventory []findings.Package) ([]query, []pkgKey) {
	seen := make(map[pkgKey]struct{}, len(inventory))
	queries := make([]query, 0, len(inventory))
	keys := make([]pkgKey, 0, len(inventory))

	for _, p := range inventory {
		osvEco, ok := ecosystem(p.Ecosystem)
		if !ok || p.Name == "" || p.Version == "" {
			continue
		}
		key := pkgKey{ecosystem: p.Ecosystem, name: p.Name, version: p.Version}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		q := query{Version: p.Version}
		q.Package.Name = p.Name
		q.Package.Ecosystem = osvEco
		queries = append(queries, q)
		keys = append(keys, key)
	}
	return queries, keys
}

// ecosystems maps Trivy's ecosystem names onto OSV's. Ecosystem strings Trivy
// reports for OS packages (os-apk, os-rpm, os-deb) have no single OSV
// ecosystem without the distribution, so they are not mapped.
var ecosystems = map[string]string{
	"npm":             "npm",
	"pypi":            "PyPI",
	"go":              "Go",
	"maven":           "Maven",
	"gem":             "RubyGems",
	"nuget":           "NuGet",
	"cargo":           "crates.io",
	"composer":        "Packagist",
	"composer-vendor": "Packagist",
	"conan":           "ConanCenter",
	"hex":             "Hex",
	"pub":             "Pub",
	"julia":           "Julia",
	"swift":           "SwiftURL",
}

// ecosystem returns the OSV name for a Trivy-style ecosystem.
func ecosystem(name string) (string, bool) {
	osvName, ok := ecosystems[strings.ToLower(name)]
	return osvName, ok
}

// do performs one API request and decodes the JSON response.
func (m *Matcher) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("osv: encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	base := m.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("User-Agent", m.UserAgent)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("osv: request %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("osv: decode %s response: %w", path, err)
	}
	return nil
}

// The types below mirror only the OSV API fields the matcher consumes.

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package   queryPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns         []vulnID `json:"vulns"`
	NextPageToken string   `json:"next_page_token"`
}

type vulnID struct {
	ID string `json:"id"`
}

type vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Aliases          []string         `json:"aliases"`
	DatabaseSpecific databaseSpecific `json:"database_specific"`
}

// databaseSpecific carries the fields OSV stores per source. bastion consumes
// only the severity OSV's own records publish there.
type databaseSpecific struct {
	Severity string `json:"severity"`
}
