package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/app"
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
	c.cancel()
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
	if !scan.Error.Valid || !strings.Contains(scan.Error.String, "context canceled") {
		t.Fatalf("scan error = %+v, want context canceled", scan.Error)
	}
}
