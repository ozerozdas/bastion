package store_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// createTestAsset resolves the asset a test scans.
func createTestAsset(ctx context.Context, t *testing.T, queries *sqlcdb.Queries) sqlcdb.Asset {
	t.Helper()

	asset, err := queries.GetOrCreateAsset(ctx, sqlcdb.GetOrCreateAssetParams{
		Kind:         "path",
		DisplayName:  "project",
		Ref:          "/tmp/project",
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-11T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}
	return asset
}

// createTestScan queues one scan of assetID, as the CLI or a job would before
// the scanners start.
func createTestScan(ctx context.Context, t *testing.T, queries *sqlcdb.Queries, assetID int64) sqlcdb.Scan {
	t.Helper()

	scan, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: assetID,
		Status:  "queued",
		Trigger: "cli",
	})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	return scan
}

// testFinding builds a normalized finding with the fingerprint a scanner
// adapter would set.
func testFinding(assetID int64, kind findings.Type, ruleID string, severity findings.Severity) findings.Finding {
	f := findings.Finding{
		AssetID:     assetID,
		Type:        kind,
		RuleID:      ruleID,
		Severity:    severity,
		Title:       "example finding " + ruleID,
		PackageName: "example",
		Ecosystem:   "go",
		Scanner:     "trivy",
		Occurrences: 1,
	}
	f.Fingerprint = findings.Fingerprint(assetID, f)
	return f
}

func TestSaveScanResultTracksFirstSeen(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	persisting := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	persisting.References = []string{"https://example.test/CVE-2026-0001"}
	introduced := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium)

	scanIDs := make([]int64, 0, 3)
	for i := range 3 {
		scan := createTestScan(ctx, t, queries, asset.ID)
		res := store.ScanResult{
			Status:     store.ScanStatusSucceeded,
			TargetRef:  "sha-abc123",
			FinishedAt: timeAt(10 + i),
			Findings:   []findings.Finding{persisting},
		}
		if i > 0 {
			// The second scan is where the second fingerprint first appears.
			res.Findings = append(res.Findings, introduced)
		}
		if err := store.SaveScanResult(ctx, db, scan.ID, res); err != nil {
			t.Fatalf("SaveScanResult(scan %d): %v", i+1, err)
		}
		scanIDs = append(scanIDs, scan.ID)
	}

	want := []map[string]int64{
		{persisting.Fingerprint: scanIDs[0]},
		{persisting.Fingerprint: scanIDs[0], introduced.Fingerprint: scanIDs[1]},
		{persisting.Fingerprint: scanIDs[0], introduced.Fingerprint: scanIDs[1]},
	}
	for i, scanID := range scanIDs {
		rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scanID})
		if err != nil {
			t.Fatalf("ListFindingsByScan(%d): %v", scanID, err)
		}
		if len(rows) != len(want[i]) {
			t.Fatalf("scan %d has %d findings, want %d", i+1, len(rows), len(want[i]))
		}
		for _, row := range rows {
			firstSeen, ok := want[i][row.Fingerprint]
			if !ok {
				t.Fatalf("scan %d has unexpected fingerprint %s", i+1, row.Fingerprint)
			}
			if !row.FirstSeenScanID.Valid || row.FirstSeenScanID.Int64 != firstSeen {
				t.Fatalf("scan %d: first_seen_scan_id of %s = %+v, want %d", i+1, row.Fingerprint, row.FirstSeenScanID, firstSeen)
			}
			if row.AssetID != asset.ID {
				t.Fatalf("scan %d: asset_id = %d, want %d", i+1, row.AssetID, asset.ID)
			}
		}
	}

	// The persisting fingerprint keeps its first scan and its original
	// references-free row count; one row per scan, never one per occurrence.
	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scanIDs[0]})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	got := rows[0]
	if got.Occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", got.Occurrences)
	}
	if got.ReferencesJSON != `["https://example.test/CVE-2026-0001"]` {
		t.Fatalf("references_json = %s, want the encoded references", got.ReferencesJSON)
	}
	if got.Status != "open" || got.Severity != string(findings.SeverityHigh) {
		t.Fatalf("finding = %+v, want an open high finding", got)
	}
}

func TestSaveScanResultRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)

	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	res := store.ScanResult{
		Status:      store.ScanStatusSucceeded,
		ScannerRuns: []store.ScannerRun{{Scanner: "trivy", Status: "succeeded"}},
		Packages:    []findings.Package{{Ecosystem: "go", Name: "example"}},
		// The same fingerprint twice in one scan violates
		// UNIQUE (scan_id, fingerprint) and must abort the whole transaction.
		Findings: []findings.Finding{finding, finding},
	}
	err := store.SaveScanResult(ctx, db, scan.ID, res)
	if err == nil {
		t.Fatal("SaveScanResult with a duplicate fingerprint succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Fatalf("SaveScanResult error = %v, want the fingerprint unique constraint failure", err)
	}

	var runs, packages, rows int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scanner_runs WHERE scan_id = ?`, scan.ID).Scan(&runs); err != nil {
		t.Fatalf("count scanner_runs: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages WHERE scan_id = ?`, scan.ID).Scan(&packages); err != nil {
		t.Fatalf("count packages: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scan.ID).Scan(&rows); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if runs != 0 || packages != 0 || rows != 0 {
		t.Fatalf("rows after rollback = %d scanner_runs, %d packages, %d findings, want all 0", runs, packages, rows)
	}

	// The finish step was part of the same transaction, so the scan is still
	// queued and has no finish time.
	got, err := queries.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != "queued" || got.FinishedAt.Valid {
		t.Fatalf("scan after rollback = %+v, want queued and unfinished", got)
	}
}

func TestSaveScanResultPersistsFailedScan(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)
	finding := testFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityCritical)

	res := store.ScanResult{
		Status:     store.ScanStatusFailed,
		TargetRef:  "sha-failed",
		Error:      "scan: scanner failed: trivy",
		FinishedAt: timeAt(12),
		ScannerRuns: []store.ScannerRun{
			{Scanner: "gitleaks", ScannerVersion: "8.30.1", Status: "succeeded", DurationMS: durationMS(42)},
			{Scanner: "trivy", ScannerVersion: "0.76.2", Status: "failed", Error: "db unavailable"},
		},
		Packages: []findings.Package{{Ecosystem: "go", Name: "example", Version: "1.0.0", Direct: boolPtr(true)}},
		Findings: []findings.Finding{finding},
	}
	if err := store.SaveScanResult(ctx, db, scan.ID, res); err != nil {
		t.Fatalf("SaveScanResult(failed scan): %v", err)
	}

	got, err := queries.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != store.ScanStatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.FinishedAt.Valid || got.FinishedAt.String != timeAt(12).UTC().Format(timeLayout) {
		t.Fatalf("finished_at = %+v, want %s", got.FinishedAt, timeAt(12).UTC().Format(timeLayout))
	}
	if !got.Error.Valid || got.Error.String != res.Error {
		t.Fatalf("error = %+v, want %q", got.Error, res.Error)
	}
	if !got.TargetRef.Valid || got.TargetRef.String != "sha-failed" {
		t.Fatalf("target_ref = %+v, want sha-failed", got.TargetRef)
	}

	var runs int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scanner_runs WHERE scan_id = ?`, scan.ID).Scan(&runs); err != nil {
		t.Fatalf("count scanner_runs: %v", err)
	}
	if runs != 2 {
		t.Fatalf("scanner_runs = %d, want 2", runs)
	}

	var failedError sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT error FROM scanner_runs WHERE scan_id = ? AND scanner = 'trivy'`, scan.ID).Scan(&failedError); err != nil {
		t.Fatalf("read trivy run: %v", err)
	}
	if !failedError.Valid || failedError.String != "db unavailable" {
		t.Fatalf("trivy run error = %+v, want db unavailable", failedError)
	}

	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings = %d, want the partial finding", len(rows))
	}
	if !rows[0].FirstSeenScanID.Valid || rows[0].FirstSeenScanID.Int64 != scan.ID {
		t.Fatalf("first_seen_scan_id = %+v, want the failing scan %d", rows[0].FirstSeenScanID, scan.ID)
	}
}

func TestGetOrCreateAssetIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	first := createTestAsset(ctx, t, queries)
	second, err := queries.GetOrCreateAsset(ctx, sqlcdb.GetOrCreateAssetParams{
		Kind:         "path",
		DisplayName:  "project renamed",
		Ref:          "/tmp/project",
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-11T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset (second call): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("second call created id %d, want the existing %d", second.ID, first.ID)
	}
	if second.DisplayName != "project renamed" {
		t.Fatalf("display_name = %q, want the refreshed name", second.DisplayName)
	}
	if second.CreatedAt != first.CreatedAt {
		t.Fatalf("created_at = %q, want the original %q", second.CreatedAt, first.CreatedAt)
	}

	assets, err := queries.ListAssets(ctx)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("ListAssets returned %d assets, want 1", len(assets))
	}

	archived, err := queries.ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ArchivedAt: sql.NullString{String: "2026-11-11T13:00:00Z", Valid: true},
		ID:         first.ID,
	})
	if err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}
	if !archived.ArchivedAt.Valid || archived.ArchivedAt.String != "2026-11-11T13:00:00Z" {
		t.Fatalf("archived_at = %+v, want the archived timestamp", archived.ArchivedAt)
	}
	assets, err = queries.ListAssets(ctx)
	if err != nil {
		t.Fatalf("ListAssets after archive: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("ListAssets returned %d assets after archive, want 0", len(assets))
	}
}

func TestScanLifecycleAndListing(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)

	// The first transition records started_at; a later one keeps it.
	for _, startedAt := range []string{"2026-11-11T10:01:00Z", "2026-11-11T10:05:00Z"} {
		if err := queries.MarkScanRunning(ctx, sqlcdb.MarkScanRunningParams{
			StartedAt: sql.NullString{String: startedAt, Valid: true},
			ID:        scan.ID,
		}); err != nil {
			t.Fatalf("MarkScanRunning: %v", err)
		}
	}
	running, err := queries.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if running.Status != "running" || !running.StartedAt.Valid || running.StartedAt.String != "2026-11-11T10:01:00Z" {
		t.Fatalf("running scan = %+v, want running with the first started_at", running)
	}

	findingsToSave := []findings.Finding{
		testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical),
		testFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityLow),
		testFinding(asset.ID, findings.TypeSecret, "aws-access-key", findings.SeverityCritical),
	}
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: findingsToSave,
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	// A second scan makes "newest first" observable.
	newest := createTestScan(ctx, t, queries, asset.ID)
	scans, err := queries.ListScansByAsset(ctx, sqlcdb.ListScansByAssetParams{AssetID: asset.ID, Limit: 2})
	if err != nil {
		t.Fatalf("ListScansByAsset: %v", err)
	}
	if len(scans) != 2 || scans[0].ID != newest.ID || scans[1].ID != scan.ID {
		t.Fatalf("ListScansByAsset = %+v, want [%d %d]", scans, newest.ID, scan.ID)
	}
	limited, err := queries.ListScansByAsset(ctx, sqlcdb.ListScansByAssetParams{AssetID: asset.ID, Limit: 1})
	if err != nil {
		t.Fatalf("ListScansByAsset(limit 1): %v", err)
	}
	if len(limited) != 1 || limited[0].ID != newest.ID {
		t.Fatalf("ListScansByAsset(limit 1) = %+v, want the newest scan", limited)
	}

	all, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(all) != len(findingsToSave) {
		t.Fatalf("findings = %d, want %d", len(all), len(findingsToSave))
	}
	// Most severe first, so both critical findings lead.
	if all[0].Severity != string(findings.SeverityCritical) || all[1].Severity != string(findings.SeverityCritical) {
		t.Fatalf("severity order = %q, %q, want critical first", all[0].Severity, all[1].Severity)
	}
	if all[2].Severity != string(findings.SeverityLow) {
		t.Fatalf("last severity = %q, want the low finding", all[2].Severity)
	}

	secrets, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID: scan.ID,
		Type:   string(findings.TypeSecret),
	})
	if err != nil {
		t.Fatalf("ListFindingsByScan(type secret): %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("secret findings = %d, want 2", len(secrets))
	}

	low, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID:   scan.ID,
		Severity: string(findings.SeverityLow),
	})
	if err != nil {
		t.Fatalf("ListFindingsByScan(severity low): %v", err)
	}
	if len(low) != 1 || low[0].Type != string(findings.TypeSecret) {
		t.Fatalf("low findings = %+v, want the single low secret", low)
	}

	none, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID:   scan.ID,
		Type:     string(findings.TypeVulnerability),
		Severity: string(findings.SeverityLow),
	})
	if err != nil {
		t.Fatalf("ListFindingsByScan(vulnerability, low): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("vulnerability+low findings = %d, want 0", len(none))
	}
}

// timeAt is a fixed UTC timestamp for deterministic assertions.
func timeAt(hour int) time.Time {
	return time.Date(2026, time.November, 11, hour, 0, 0, 0, time.UTC)
}

// timeLayout is the timestamp format the store writes (PROJECT_SPEC.md §5).
const timeLayout = time.RFC3339

func durationMS(ms int64) *int64 { return &ms }

func boolPtr(v bool) *bool { return &v }
