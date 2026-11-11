package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ozerozdas/bastion/internal/app"
	githubclient "github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// fakeScanner is a Scanner + Normalizer pair for pipeline tests: it returns
// pre-built findings and never touches a scanner library. normalize overrides
// the pre-built list when a test needs the scanned asset.
type fakeScanner struct {
	name      string
	err       error
	findings  []findings.Finding
	normalize func(*scanners.RawResult, findings.Asset) ([]findings.Finding, []findings.Package, error)
}

func (f *fakeScanner) Name() string                     { return f.name }
func (f *fakeScanner) Version() string                  { return "test" }
func (f *fakeScanner) Supports(sources.TargetKind) bool { return true }

func (f *fakeScanner) Scan(context.Context, *sources.Workspace, scanners.Options) (*scanners.RawResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &scanners.RawResult{Scanner: f.name}, nil
}

func (f *fakeScanner) Normalize(raw *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	if f.normalize != nil {
		return f.normalize(raw, asset)
	}
	return f.findings, []findings.Package{}, nil
}

// cancelingScanner simulates Ctrl-C arriving while a scanner is running.
type cancelingScanner struct {
	cancel context.CancelFunc
}

func (c *cancelingScanner) Name() string                     { return "interrupted" }
func (c *cancelingScanner) Version() string                  { return "test" }
func (c *cancelingScanner) Supports(sources.TargetKind) bool { return true }

func (c *cancelingScanner) Scan(ctx context.Context, _ *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
	// Ctrl-C: cancel the command context, then stop when the manager cancels
	// the job, the way a real scanner returns once its context ends.
	c.cancel()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *cancelingScanner) Normalize(*scanners.RawResult, findings.Asset) ([]findings.Finding, []findings.Package, error) {
	return nil, nil, nil
}

// testScanDeps returns production code paths with the keyring faked out: the
// database is a real SQLite file and Ctrl-C is a plain cancelable context.
func testScanDeps(t *testing.T, dataDir string) scanDeps {
	t.Helper()

	return scanDeps{
		paths:   app.Paths{DataDir: dataDir, CacheDir: filepath.Join(dataDir, "cache")},
		openDB:  store.Open,
		closeDB: (*sql.DB).Close,
		notifyContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithCancel(parent)
		},
		newScanners: func() []scanners.Scanner {
			return []scanners.Scanner{&fakeScanner{name: "fake", normalize: normalizeWithAsset}}
		},
		// A fixed key keeps secret fingerprints stable; the fake scanner never
		// HMACs anything, so it only has to be present.
		hmacKey: func() ([]byte, error) { return bytes.Repeat([]byte{1}, 32), nil },
		// --repo tests replace these with fakes; a path scan never calls them.
		githubToken: nil,
		newGitHub:   nil,
		version:     "test",
	}
}

// normalizeWithAsset builds a finding whose fingerprint comes from the asset
// the scan resolved to, the way the real adapters do.
func normalizeWithAsset(_ *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	f := findings.Finding{
		AssetID:  asset.ID,
		Type:     findings.TypeSecret,
		RuleID:   "generic-api-key",
		Severity: findings.SeverityHigh,
		Title:    "example secret",
		Location: "config/app.env:1",
		Scanner:  "fake",
	}
	f.Fingerprint = findings.Fingerprint(asset.ID, f)
	return []findings.Finding{f}, nil, nil
}

// runScanJSON runs one CLI scan and decodes the printed document.
func runScanJSON(t *testing.T, dir string, deps scanDeps) (scanOutput, error) {
	t.Helper()

	var out bytes.Buffer
	runErr := runScan(context.Background(), &out, &scanOptions{path: dir, format: scanFormatJSON}, deps)

	var doc scanOutput
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("decode scan output: %v\n%s", err, out.String())
		}
	}
	return doc, runErr
}

func testFinding(ruleID string) findings.Finding {
	f := findings.Finding{
		AssetID:  1,
		Type:     findings.TypeSecret,
		RuleID:   ruleID,
		Severity: findings.SeverityHigh,
		Location: "config/credentials:1",
		Scanner:  "good",
	}
	f.Fingerprint = findings.Fingerprint(f.AssetID, f)
	return f
}

func TestScanTargetPartialFailure(t *testing.T) {
	good := &fakeScanner{name: "good", findings: []findings.Finding{testFinding("aws-access-token")}}
	bad := &fakeScanner{name: "bad", err: errors.New("vuln db download failed")}

	out, err := scanTarget(context.Background(), sources.KindPath,
		[]scanners.Scanner{good, bad}, &sources.Workspace{Dir: "/tmp/ws"},
		findings.Asset{ID: 1, Kind: findings.AssetKindPath}, scanners.Options{})

	if err == nil {
		t.Fatal("scanTarget returned no error although a scanner failed")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error %q does not name the failed scanner", err)
	}
	if strings.Contains(err.Error(), "good") {
		t.Fatalf("error %q names a scanner that succeeded", err)
	}

	// The other scanner's findings are still part of the output.
	if len(out.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(out.Findings), out.Findings)
	}
	if out.Findings[0].Occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", out.Findings[0].Occurrences)
	}

	if len(out.ScannerRuns) != 2 {
		t.Fatalf("got %d scanner runs, want 2: %+v", len(out.ScannerRuns), out.ScannerRuns)
	}
	runs := map[string]scannerRun{}
	for _, run := range out.ScannerRuns {
		runs[run.Scanner] = run
	}
	if run := runs["good"]; run.Status != "succeeded" || run.Error != "" {
		t.Fatalf("good run = %+v, want succeeded without error", run)
	}
	if run := runs["bad"]; run.Status != "failed" || !strings.Contains(run.Error, "vuln db download failed") {
		t.Fatalf("bad run = %+v, want failed with the scanner error", run)
	}
}

func TestScanTargetMergesDuplicateFingerprints(t *testing.T) {
	// The same rule fires twice (two Dockerfile stages); one scan, one finding.
	dup := testFinding("DS-0001")
	good := &fakeScanner{name: "good", findings: []findings.Finding{dup, dup}}

	out, err := scanTarget(context.Background(), sources.KindPath,
		[]scanners.Scanner{good}, &sources.Workspace{Dir: "/tmp/ws"},
		findings.Asset{ID: 1, Kind: findings.AssetKindPath}, scanners.Options{})
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(out.Findings))
	}
	if out.Findings[0].Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", out.Findings[0].Occurrences)
	}
}

func TestRunScanReusesOneAssetPerPath(t *testing.T) {
	dataDir := t.TempDir()
	scanDir := t.TempDir()
	deps := testScanDeps(t, dataDir)

	first, err := runScanJSON(t, scanDir, deps)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	second, err := runScanJSON(t, scanDir, deps)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	// One asset row for the directory, with the absolute cleaned path as ref.
	if first.Asset.ID == 0 || second.Asset.ID != first.Asset.ID {
		t.Fatalf("asset ids = %d and %d, want one non-zero asset", first.Asset.ID, second.Asset.ID)
	}
	if want := filepath.Clean(scanDir); first.Asset.Ref != want || first.Asset.DisplayName != filepath.Base(want) {
		t.Fatalf("asset = %+v, want ref %q and name %q", first.Asset, want, filepath.Base(want))
	}

	// Each run is its own scan.
	if first.ScanID == 0 || second.ScanID == first.ScanID {
		t.Fatalf("scan ids = %d and %d, want two different non-zero scans", first.ScanID, second.ScanID)
	}

	if len(first.Findings) != 1 || len(second.Findings) != 1 {
		t.Fatalf("findings = %d and %d, want 1 each", len(first.Findings), len(second.Findings))
	}
	firstFinding, secondFinding := first.Findings[0], second.Findings[0]
	if firstFinding.AssetID != first.Asset.ID || secondFinding.AssetID != first.Asset.ID {
		t.Fatalf("finding asset ids = %d and %d, want %d", firstFinding.AssetID, secondFinding.AssetID, first.Asset.ID)
	}
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across scans of one path: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}

	// The database agrees: one asset, two succeeded scans, and the second
	// finding remembers the first scan as its first sighting.
	db, err := store.Open(context.Background(), deps.paths.DBPath())
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}()
	ctx := context.Background()
	queries := sqlcdb.New(db)

	assets, err := queries.ListAssets(ctx)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != first.Asset.ID {
		t.Fatalf("assets = %+v, want only %d", assets, first.Asset.ID)
	}

	scans, err := queries.ListScansByAsset(ctx, sqlcdb.ListScansByAssetParams{AssetID: first.Asset.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListScansByAsset: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("scans = %d, want 2", len(scans))
	}
	for _, scan := range scans {
		if scan.Status != store.ScanStatusSucceeded || scan.Trigger != store.ScanTriggerCLI || !scan.StartedAt.Valid {
			t.Fatalf("scan = %+v, want a started, succeeded cli scan", scan)
		}
	}

	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: second.ScanID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("second scan findings = %d, want 1", len(rows))
	}
	if rows[0].Fingerprint != firstFinding.Fingerprint {
		t.Fatalf("stored fingerprint = %q, want %q", rows[0].Fingerprint, firstFinding.Fingerprint)
	}
	if !rows[0].FirstSeenScanID.Valid || rows[0].FirstSeenScanID.Int64 != first.ScanID {
		t.Fatalf("first_seen_scan_id = %+v, want the first scan %d", rows[0].FirstSeenScanID, first.ScanID)
	}
}

func TestRunScanNoStoreWritesNoDatabase(t *testing.T) {
	// The data directory does not exist yet: nothing may create it.
	dataDir := filepath.Join(t.TempDir(), "data")
	scanDir := t.TempDir()
	deps := testScanDeps(t, dataDir)
	deps.openDB = func(context.Context, string) (*sql.DB, error) {
		t.Fatal("--no-store opened the database")
		return nil, nil
	}

	var out bytes.Buffer
	err := runScan(context.Background(), &out, &scanOptions{path: scanDir, format: scanFormatJSON, noStore: true}, deps)
	if err != nil {
		t.Fatalf("scan --no-store: %v", err)
	}

	var doc scanOutput
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, out.String())
	}
	if doc.Asset.ID != 0 || doc.ScanID != 0 {
		t.Fatalf("asset id = %d, scan id = %d, want the P0 zero ids", doc.Asset.ID, doc.ScanID)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(doc.Findings))
	}
	if _, err := os.Stat(deps.paths.DBPath()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("database file exists after --no-store: %v", err)
	}
	if _, err := os.Stat(deps.paths.DataDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data directory exists after --no-store: %v", err)
	}
}

func TestRunScanCanceledIsPersisted(t *testing.T) {
	scanDir := t.TempDir()
	deps := testScanDeps(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	deps.notifyContext = func(context.Context) (context.Context, context.CancelFunc) {
		return ctx, cancel
	}
	deps.newScanners = func() []scanners.Scanner {
		return []scanners.Scanner{&cancelingScanner{cancel: cancel}}
	}

	doc, runErr := runScanJSON(t, scanDir, deps)
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("runScan error = %v, want context.Canceled", runErr)
	}
	if doc.ScanID == 0 || doc.Asset.ID == 0 {
		t.Fatalf("scan id = %d, asset id = %d, want both set", doc.ScanID, doc.Asset.ID)
	}

	db, err := store.Open(context.Background(), deps.paths.DBPath())
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}()

	scan, err := sqlcdb.New(db).GetScan(context.Background(), doc.ScanID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Status != store.ScanStatusCanceled {
		t.Fatalf("scan status = %q, want canceled", scan.Status)
	}
	// The manager persists a canceled scan without an error: the status is the
	// signal, and an interrupted scan is not a failure.
	if scan.Error.Valid {
		t.Fatalf("scan error = %+v, want none", scan.Error)
	}
}

// severityFinding builds a finding whose fingerprint depends on ruleID, so a
// test can list findings of different severities without them merging.
func severityFinding(ruleID string, severity findings.Severity) findings.Finding {
	f := findings.Finding{
		AssetID:  1,
		Type:     findings.TypeVulnerability,
		RuleID:   ruleID,
		Severity: severity,
		Title:    ruleID + " finding",
		Location: "app/go.mod:1",
		Scanner:  "fake",
	}
	f.Fingerprint = findings.Fingerprint(f.AssetID, f)
	return f
}

func TestScanOptionsValidate(t *testing.T) {
	tests := []struct {
		name string
		opts scanOptions
		want string
	}{
		{
			name: "neither target",
			opts: scanOptions{format: scanFormatJSON},
			want: "one of --path or --repo",
		},
		{
			name: "both targets",
			opts: scanOptions{path: "/tmp", repo: "acme/widgets", format: scanFormatJSON},
			want: "mutually exclusive",
		},
		{
			name: "unknown format",
			opts: scanOptions{path: "/tmp", format: "xml"},
			want: "unsupported format",
		},
		{
			name: "unknown fail-on",
			opts: scanOptions{path: "/tmp", format: scanFormatJSON, failOn: "severe"},
			want: "unsupported --fail-on",
		},
		{
			name: "absolute skip dir",
			opts: scanOptions{path: "/tmp", format: scanFormatJSON, skipDirs: []string{"/tmp/testdata"}},
			want: "relative to the scan root",
		},
		{
			name: "escaping skip dir",
			opts: scanOptions{path: "/tmp", format: scanFormatJSON, skipDirs: []string{"../up"}},
			want: "relative to the scan root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate() = %v, want an error containing %q", err, tt.want)
			}
		})
	}

	for _, opts := range []scanOptions{
		{path: "/tmp", format: scanFormatJSON},
		{path: "/tmp", format: scanFormatTable, failOn: "high"},
		{repo: "acme/widgets", format: scanFormatSARIF, failOn: "low"},
		{path: "/tmp", format: scanFormatJSON, skipDirs: []string{"testdata", "web/dist"}},
	} {
		if err := opts.validate(); err != nil {
			t.Errorf("validate(%+v) = %v, want nil", opts, err)
		}
	}
}

func TestParseRepoSpec(t *testing.T) {
	valid := []struct {
		in   string
		want repoSpec
	}{
		{
			in:   "acme/widgets",
			want: repoSpec{fullName: "acme/widgets", owner: "acme", name: "widgets"},
		},
		{
			in:   "acme/widgets@main",
			want: repoSpec{fullName: "acme/widgets", owner: "acme", name: "widgets", ref: "main"},
		},
		{
			in:   "acme/widgets@release/1.x",
			want: repoSpec{fullName: "acme/widgets", owner: "acme", name: "widgets", ref: "release/1.x"},
		},
	}
	for _, tt := range valid {
		got, err := parseRepoSpec(tt.in)
		if err != nil {
			t.Fatalf("parseRepoSpec(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("parseRepoSpec(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}

	invalid := []string{"", "widgets", "acme/widgets/extra", "/widgets", "acme/", "acme/wid gets", "acme/widgets@", "acme/widgets@main@next"}
	for _, in := range invalid {
		if _, err := parseRepoSpec(in); err == nil {
			t.Errorf("parseRepoSpec(%q) succeeded, want an error", in)
		}
	}
}

func TestScanTableOutput(t *testing.T) {
	deps := testScanDeps(t, filepath.Join(t.TempDir(), "data"))
	deps.newScanners = func() []scanners.Scanner {
		return []scanners.Scanner{&fakeScanner{name: "fake", findings: []findings.Finding{
			severityFinding("low-rule", findings.SeverityLow),
			severityFinding("critical-rule", findings.SeverityCritical),
			severityFinding("medium-rule", findings.SeverityMedium),
			severityFinding("high-rule", findings.SeverityHigh),
		}}}
	}

	var out bytes.Buffer
	if err := runScan(context.Background(), &out, &scanOptions{
		path: t.TempDir(), format: scanFormatTable, noStore: true,
	}, deps); err != nil {
		t.Fatalf("scan --format table: %v\n%s", err, out.String())
	}

	got := out.String()
	for _, column := range []string{"SEVERITY", "TYPE", "RULE", "PACKAGE/LOCATION", "TITLE"} {
		if !strings.Contains(got, column) {
			t.Fatalf("table output has no %s column:\n%s", column, got)
		}
	}

	// Rows are severity-sorted even though the scanner returned them unsorted.
	order := []string{"critical-rule", "high-rule", "medium-rule", "low-rule"}
	last := -1
	for _, rule := range order {
		index := strings.Index(got, rule)
		if index < 0 {
			t.Fatalf("table output has no %q row:\n%s", rule, got)
		}
		if index < last {
			t.Fatalf("table output is not severity-sorted:\n%s", got)
		}
		last = index
	}

	// PACKAGE/LOCATION falls back to the location when no package was named.
	if !strings.Contains(got, "app/go.mod:1") {
		t.Fatalf("table output has no location:\n%s", got)
	}
	if !strings.Contains(got, "4 findings: 1 critical, 1 high, 1 medium, 1 low") {
		t.Fatalf("table output has no summary line:\n%s", got)
	}
}

func TestCheckFailOn(t *testing.T) {
	list := []findings.Finding{
		severityFinding("high-rule", findings.SeverityHigh),
		severityFinding("low-rule", findings.SeverityLow),
		severityFinding("unknown-rule", findings.SeverityUnknown),
	}

	tests := []struct {
		name      string
		threshold string
		wantErr   bool
	}{
		{name: "no threshold", threshold: ""},
		{name: "critical is not reached", threshold: "critical"},
		{name: "high is reached", threshold: "high", wantErr: true},
		{name: "low is reached", threshold: "low", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkFailOn(tt.threshold, list)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("checkFailOn(%q) = %v, want nil", tt.threshold, err)
				}
				return
			}
			if !errors.Is(err, errFailOn) {
				t.Fatalf("checkFailOn(%q) = %v, want errFailOn", tt.threshold, err)
			}
		})
	}

	// An unknown severity is never "at or above" a threshold.
	if err := checkFailOn("low", []findings.Finding{severityFinding("u", findings.SeverityUnknown)}); err != nil {
		t.Fatalf("checkFailOn(low) with only an unknown severity = %v, want nil", err)
	}
	// The message states how many open findings breach the gate.
	if err := checkFailOn("high", list); !strings.Contains(err.Error(), "1 finding(s)") {
		t.Fatalf("checkFailOn message = %q, want the breach count", err)
	}
}

func TestScanFailOnExitStatus(t *testing.T) {
	deps := testScanDeps(t, filepath.Join(t.TempDir(), "data"))
	deps.newScanners = func() []scanners.Scanner {
		return []scanners.Scanner{&fakeScanner{name: "fake", findings: []findings.Finding{
			severityFinding("high-rule", findings.SeverityHigh),
		}}}
	}

	var out bytes.Buffer
	err := runScan(context.Background(), &out, &scanOptions{
		path: t.TempDir(), format: scanFormatJSON, noStore: true, failOn: "high",
	}, deps)
	if !errors.Is(err, errFailOn) {
		t.Fatalf("scan --fail-on high = %v, want errFailOn", err)
	}
	if got := exitCode(err); got != 2 {
		t.Fatalf("exit code = %d, want 2", got)
	}

	// Findings below the threshold do not fail the command.
	out.Reset()
	if err := runScan(context.Background(), &out, &scanOptions{
		path: t.TempDir(), format: scanFormatJSON, noStore: true, failOn: "critical",
	}, deps); err != nil {
		t.Fatalf("scan --fail-on critical = %v, want nil", err)
	}

	// A broken scan is an error, not a threshold breach: exit code 1.
	if got := exitCode(errors.New("scanner failed")); got != 1 {
		t.Fatalf("exit code of a scanner error = %d, want 1", got)
	}
}

// requestLog records the paths a fake GitHub server was asked for.
type requestLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *requestLog) add(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths = append(l.paths, path)
}

func (l *requestLog) has(path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Contains(l.paths, path)
}

// fakeGitHubServer serves the three endpoints a repo scan calls: repository
// metadata, ref resolution and the commit tarball. No test reaches GitHub.
func fakeGitHubServer(t *testing.T, log *requestLog, defaultBranch, sha string, archive []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		log.add(path)
		switch {
		case path == "/repos/acme/widgets":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"full_name":      "acme/widgets",
				"name":           "widgets",
				"owner":          map[string]string{"login": "acme"},
				"default_branch": defaultBranch,
			})
		case strings.HasPrefix(path, "/repos/acme/widgets/commits/"):
			_, _ = io.WriteString(w, sha)
		case strings.HasPrefix(path, "/repos/acme/widgets/tarball/"):
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// repoArchive builds a gzipped tarball the GitHub source can unpack: one entry
// below the top-level owner-repo-sha directory that the source strips.
func repoArchive(t *testing.T, sha string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("# widgets\n")
	hdr := &tar.Header{
		Name: "acme-widgets-" + sha + "/README.md",
		Mode: 0o644,
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

// repoScanDeps wires a scan against the fake GitHub server.
func repoScanDeps(t *testing.T, dataDir, baseURL string) scanDeps {
	t.Helper()
	deps := testScanDeps(t, dataDir)
	deps.githubToken = func(context.Context, *sql.DB) (string, error) { return "test-token", nil }
	deps.newGitHub = func(token string) (gitHubClient, error) {
		return githubclient.New(githubclient.Config{Token: token, BaseURL: baseURL})
	}
	return deps
}

func TestRunScanRepoNoStore(t *testing.T) {
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	log := &requestLog{}
	srv := fakeGitHubServer(t, log, "trunk", sha, repoArchive(t, sha))

	deps := repoScanDeps(t, filepath.Join(t.TempDir(), "data"), srv.URL)
	deps.openDB = func(context.Context, string) (*sql.DB, error) {
		t.Fatal("--no-store opened the database")
		return nil, nil
	}

	var out bytes.Buffer
	if err := runScan(context.Background(), &out, &scanOptions{
		repo: "acme/widgets", format: scanFormatJSON, noStore: true,
	}, deps); err != nil {
		t.Fatalf("scan --repo --no-store: %v\n%s", err, out.String())
	}

	var doc scanOutput
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, out.String())
	}
	if doc.Asset.Kind != findings.AssetKindRepo || doc.Asset.Ref != "acme/widgets" {
		t.Fatalf("asset = %+v, want the repo asset acme/widgets", doc.Asset)
	}
	if doc.Asset.ID != 0 || doc.ScanID != 0 {
		t.Fatalf("asset id = %d, scan id = %d, want zero ids", doc.Asset.ID, doc.ScanID)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(doc.Findings))
	}

	// No ref means the repository's default branch, resolved to its SHA before
	// the tarball is fetched.
	if !log.has("/repos/acme/widgets") {
		t.Errorf("requests = %v, want repository metadata", log.paths)
	}
	if !log.has("/repos/acme/widgets/commits/trunk") {
		t.Errorf("requests = %v, want the default branch resolved", log.paths)
	}
	if !log.has("/repos/acme/widgets/tarball/" + sha) {
		t.Errorf("requests = %v, want the resolved commit tarball", log.paths)
	}

	if _, err := os.Stat(deps.paths.DBPath()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("database file exists after --no-store: %v", err)
	}
}

func TestRunScanRepoStoresAsset(t *testing.T) {
	const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	log := &requestLog{}
	srv := fakeGitHubServer(t, log, "trunk", sha, repoArchive(t, sha))

	deps := repoScanDeps(t, t.TempDir(), srv.URL)
	var out bytes.Buffer
	if err := runScan(context.Background(), &out, &scanOptions{
		repo: "acme/widgets@release/1.x", format: scanFormatJSON,
	}, deps); err != nil {
		t.Fatalf("scan --repo: %v\n%s", err, out.String())
	}

	var doc scanOutput
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, out.String())
	}
	if doc.Asset.ID == 0 || doc.ScanID == 0 {
		t.Fatalf("asset id = %d, scan id = %d, want both stored", doc.Asset.ID, doc.ScanID)
	}
	if doc.Asset.Ref != "acme/widgets" || doc.Asset.Kind != findings.AssetKindRepo {
		t.Fatalf("asset = %+v, want the repo asset acme/widgets", doc.Asset)
	}

	// An explicit ref is resolved instead of the default branch.
	if !log.has("/repos/acme/widgets/commits/release/1.x") {
		t.Errorf("requests = %v, want the ref resolved", log.paths)
	}

	db, err := store.Open(context.Background(), deps.paths.DBPath())
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}()
	ctx := context.Background()
	queries := sqlcdb.New(db)

	assets, err := queries.ListAssets(ctx)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("assets = %+v, want one repo asset", assets)
	}
	if !assets[0].DefaultBranch.Valid || assets[0].DefaultBranch.String != "trunk" {
		t.Fatalf("default_branch = %+v, want trunk", assets[0].DefaultBranch)
	}

	scan, err := queries.GetScan(ctx, doc.ScanID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Status != store.ScanStatusSucceeded || scan.Trigger != store.ScanTriggerCLI {
		t.Fatalf("scan = %+v, want a succeeded cli scan", scan)
	}
	if !scan.TargetRef.Valid || scan.TargetRef.String != sha {
		t.Fatalf("target_ref = %+v, want %s", scan.TargetRef, sha)
	}
}
