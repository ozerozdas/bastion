package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// openTestDB opens a fresh database in a temporary directory, so no test
// touches the user's real bastion.db.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	return db
}

// seedAsset resolves an asset the way a scan would.
func seedAsset(t *testing.T, db *sql.DB, kind findings.AssetKind, ref, displayName string) findings.Asset {
	t.Helper()

	asset, err := store.GetOrCreateAsset(context.Background(), db, findings.Asset{
		Kind:        kind,
		Ref:         ref,
		DisplayName: displayName,
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(%q): %v", ref, err)
	}
	return asset
}

// seedScan persists one finished scan with its findings and returns its id.
func seedScan(t *testing.T, db *sql.DB, assetID int64, status string, finishedAt time.Time, list ...findings.Finding) int64 {
	t.Helper()

	scanID, err := store.StartScan(context.Background(), db, assetID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan(asset %d): %v", assetID, err)
	}
	result := store.ScanResult{Status: status, FinishedAt: finishedAt, Findings: list}
	if status == store.ScanStatusFailed {
		result.Error = "trivy: db unavailable"
	}
	if err := store.SaveScanResult(context.Background(), db, scanID, result); err != nil {
		t.Fatalf("SaveScanResult(scan %d): %v", scanID, err)
	}
	return scanID
}

// newFinding builds a normalized finding whose fingerprint a scanner adapter
// would produce. Rule ids must differ within one asset and scan.
func newFinding(assetID int64, kind findings.Type, ruleID string, severity findings.Severity) findings.Finding {
	finding := findings.Finding{
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
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// at is a UTC timestamp on the seeded day; the hour keeps scans ordered.
func at(hour int) time.Time {
	return time.Date(2026, 11, 10, hour, 0, 0, 0, time.UTC)
}

// TestDashboardAggregates seeds two live assets and one archived asset, with
// older and newer scans and an ignored finding, and asserts every aggregate
// exactly.
func TestDashboardAggregates(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/archived", "Archived")

	// Alpha: two succeeded scans; only the newer one counts.
	alphaOldCritical := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	alphaOldMisconfig := newFinding(alpha.ID, findings.TypeMisconfig, "CKV_AWS_1", findings.SeverityMedium)
	scanA1 := seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(10), alphaOldCritical, alphaOldMisconfig)

	alphaCritical := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityCritical)
	alphaSecret := newFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	alphaLicense := newFinding(alpha.ID, findings.TypeLicense, "GPL-3.0", findings.SeverityLow)
	scanA2 := seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(11), alphaCritical, alphaSecret, alphaLicense)

	// A newer failed scan persists partial results; it must not shadow A2.
	failedCritical := newFinding(alpha.ID, findings.TypeSecret, "private-key", findings.SeverityCritical)
	scanA3 := seedScan(t, db, alpha.ID, store.ScanStatusFailed, at(12), failedCritical)

	// Beta: the high finding is ignored, so it is open nowhere.
	betaHigh := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0003", findings.SeverityHigh)
	betaMedium := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0004", findings.SeverityMedium)
	betaUnknown := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0005", findings.SeverityUnknown)
	scanB1 := seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(9), betaHigh, betaMedium, betaUnknown)
	scanB2 := seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(13), betaHigh, betaMedium, betaUnknown)
	if err := store.SetFindingState(ctx, db, beta.ID, betaHigh.Fingerprint, store.FindingStateIgnored, "accepted upstream"); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// The archived asset still owns a critical finding; it counts nowhere.
	archivedCritical := newFinding(archived.ID, findings.TypeVulnerability, "CVE-2026-0006", findings.SeverityCritical)
	archivedScan := seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(14), archivedCritical)
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(15).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	dashboard, err := service.Dashboard(ctx)
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}

	wantSeverity := reports.SeverityTotals{Critical: 1, High: 1, Medium: 1, Low: 1, Unknown: 1}
	if dashboard.TotalsBySeverity != wantSeverity {
		t.Errorf("totals_by_severity = %+v, want %+v", dashboard.TotalsBySeverity, wantSeverity)
	}
	wantTypes := reports.TypeTotals{Vulnerability: 3, Secret: 1, License: 1}
	if dashboard.TotalsByType != wantTypes {
		t.Errorf("totals_by_type = %+v, want %+v", dashboard.TotalsByType, wantTypes)
	}

	wantAssets := []reports.AssetRisk{
		{AssetID: alpha.ID, DisplayName: "Alpha", Kind: "path", Score: 1101, Critical: 1, High: 1, Medium: 0, Low: 1},
		{AssetID: beta.ID, DisplayName: "Beta", Kind: "repo", Score: 10, Critical: 0, High: 0, Medium: 1, Low: 0},
	}
	if !slices.Equal(dashboard.TopAssets, wantAssets) {
		t.Errorf("top_assets = %+v, want %+v", dashboard.TopAssets, wantAssets)
	}

	if len(dashboard.Trend) != 2 {
		t.Fatalf("trend assets = %+v, want alpha and beta", dashboard.Trend)
	}
	assertTrend(t, dashboard.Trend[0], alpha.ID, at(10), at(11), []trendPoint{
		{scanID: scanA1, criticalHigh: 1},
		{scanID: scanA2, criticalHigh: 2},
	})
	assertTrend(t, dashboard.Trend[1], beta.ID, at(9), at(13), []trendPoint{
		{scanID: scanB1, criticalHigh: 0}, // the ignored high is hidden retroactively
		{scanID: scanB2, criticalHigh: 0},
	})

	if len(dashboard.LastScans) != 2 {
		t.Fatalf("last_scans = %+v, want alpha and beta", dashboard.LastScans)
	}
	assertLastScan(t, dashboard.LastScans[0], alpha.ID, scanA3, store.ScanStatusFailed, at(12))
	assertLastScan(t, dashboard.LastScans[1], beta.ID, scanB2, store.ScanStatusSucceeded, at(13))

	for _, last := range dashboard.LastScans {
		if last.AssetID == archived.ID || last.ScanID == archivedScan {
			t.Fatalf("archived asset appears in last_scans: %+v", last)
		}
	}
}

type trendPoint struct {
	scanID       int64
	criticalHigh int
}

// assertTrend checks one asset's series: scan ids and counts in order, plus the
// finished times of the first and last point.
func assertTrend(t *testing.T, trend reports.AssetTrend, assetID int64, first, last time.Time, want []trendPoint) {
	t.Helper()

	if trend.AssetID != assetID {
		t.Fatalf("trend asset = %d, want %d", trend.AssetID, assetID)
	}
	if len(trend.Scans) != len(want) {
		t.Fatalf("trend of asset %d has %d scans, want %d: %+v", assetID, len(trend.Scans), len(want), trend.Scans)
	}
	for i, point := range trend.Scans {
		if point.ScanID != want[i].scanID || point.CriticalHighOpen != want[i].criticalHigh {
			t.Errorf("trend of asset %d point %d = %+v, want scan %d with %d", assetID, i,
				point, want[i].scanID, want[i].criticalHigh)
		}
	}
	if trend.Scans[0].FinishedAt == nil || !trend.Scans[0].FinishedAt.Equal(first) {
		t.Errorf("trend of asset %d starts at %v, want %v", assetID, trend.Scans[0].FinishedAt, first)
	}
	lastPoint := trend.Scans[len(trend.Scans)-1]
	if lastPoint.FinishedAt == nil || !lastPoint.FinishedAt.Equal(last) {
		t.Errorf("trend of asset %d ends at %v, want %v", assetID, lastPoint.FinishedAt, last)
	}
}

// assertLastScan checks one last_scans entry.
func assertLastScan(t *testing.T, got reports.LastScan, assetID, scanID int64, status string, finishedAt time.Time) {
	t.Helper()

	if got.AssetID != assetID || got.ScanID != scanID || got.Status != status {
		t.Errorf("last scan = %+v, want asset %d scan %d (%s)", got, assetID, scanID, status)
	}
	if got.FinishedAt == nil || !got.FinishedAt.Equal(finishedAt) {
		t.Errorf("last scan finished_at = %v, want %v", got.FinishedAt, finishedAt)
	}
}

// TestDashboardTrendKeepsLastTenScans proves the trend is bounded to the ten
// most recent succeeded scans and that totals only use the newest of them.
func TestDashboardTrendKeepsLastTenScans(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	finding := newFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)

	scanIDs := make([]int64, 0, 12)
	for i := range 12 {
		scanIDs = append(scanIDs, seedScan(t, db, asset.ID, store.ScanStatusSucceeded, at(i), finding))
	}

	dashboard, err := service.Dashboard(ctx)
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}

	if len(dashboard.Trend) != 1 {
		t.Fatalf("trend assets = %+v, want one", dashboard.Trend)
	}
	scans := dashboard.Trend[0].Scans
	if len(scans) != 10 {
		t.Fatalf("trend scans = %d, want the last 10", len(scans))
	}
	if scans[0].ScanID != scanIDs[2] || scans[len(scans)-1].ScanID != scanIDs[11] {
		t.Fatalf("trend scans = %+v, want scans %d..%d", scans, scanIDs[2], scanIDs[11])
	}
	for _, point := range scans {
		if point.CriticalHighOpen != 1 {
			t.Errorf("trend point %+v, want one open critical", point)
		}
	}

	// Only the newest succeeded scan feeds the totals, and the same finding is
	// one fingerprint, so it counts once.
	if dashboard.TotalsBySeverity.Critical != 1 {
		t.Errorf("totals_by_severity.critical = %d, want 1", dashboard.TotalsBySeverity.Critical)
	}
}

// TestFindingsListsLatestSucceededScanWithEffectiveStatus checks the field
// mapping and that a failed newer scan, an archived asset and an ignore
// decision are handled.
func TestFindingsListsLatestSucceededScanWithEffectiveStatus(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/archived", "Archived")

	finding := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	finding.Title = "remote code execution in lib"
	finding.PackageName = "lib"
	finding.PackageVersion = "1.0.0"
	finding.FixedVersion = "1.2.3"
	finding.Ecosystem = "go"
	finding.Location = "go.mod"
	finding.Description = "crafted input escapes the sandbox"
	finding.References = []string{"https://example.test/CVE-2026-0001"}
	finding.Occurrences = 2
	scan := seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(10), finding)

	if err := store.SetFindingState(ctx, db, alpha.ID, finding.Fingerprint, store.FindingStateFalsePositive, "scanner false match"); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// A newer failed scan and an archived asset must not show up.
	failed := newFinding(alpha.ID, findings.TypeSecret, "private-key", findings.SeverityCritical)
	seedScan(t, db, alpha.ID, store.ScanStatusFailed, at(11), failed)
	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(12),
		newFinding(archived.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityCritical))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(13).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	list, err := service.Findings(ctx, reports.Filter{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("findings = %+v, want the one succeeded finding", list)
	}

	got := list[0]
	if got.AssetID != alpha.ID || got.ScanID != scan || got.Fingerprint != finding.Fingerprint {
		t.Errorf("finding identity = %+v, want asset %d scan %d", got, alpha.ID, scan)
	}
	if got.Status != reports.FindingStatusIgnored {
		t.Errorf("status = %q, want ignored", got.Status)
	}
	if got.State != store.FindingStateFalsePositive || got.Reason != "scanner false match" {
		t.Errorf("state/reason = %q/%q, want the recorded decision", got.State, got.Reason)
	}
	if got.Title != "remote code execution in lib" || got.Severity != "high" || got.Type != "vulnerability" {
		t.Errorf("title/severity/type = %q/%q/%q", got.Title, got.Severity, got.Type)
	}
	if got.PackageName != "lib" || got.PackageVersion != "1.0.0" || got.FixedVersion != "1.2.3" ||
		got.Ecosystem != "go" || got.Location != "go.mod" {
		t.Errorf("package fields = %+v, want the stored values", got)
	}
	if got.Occurrences != 2 || got.Scanner != "trivy" {
		t.Errorf("occurrences/scanner = %d/%q", got.Occurrences, got.Scanner)
	}
	if got.Description != "crafted input escapes the sandbox" {
		t.Errorf("description = %q", got.Description)
	}
	if !slices.Equal(got.References, []string{"https://example.test/CVE-2026-0001"}) {
		t.Errorf("references = %v", got.References)
	}
	if got.FirstSeenScanID == nil || *got.FirstSeenScanID != scan {
		t.Errorf("first_seen_scan_id = %v, want %d", got.FirstSeenScanID, scan)
	}

	// A finding without references reports an empty list, never null.
	plain := newFinding(alpha.ID, findings.TypeLicense, "MIT", findings.SeverityLow)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(13), plain)
	list, err = service.Findings(ctx, reports.Filter{Type: "license"})
	if err != nil {
		t.Fatalf("Findings(license): %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("license findings = %+v, want 1", list)
	}
	if list[0].References == nil || len(list[0].References) != 0 {
		t.Errorf("references = %v, want an empty non-nil list", list[0].References)
	}
	if list[0].FixedVersion != "" || list[0].Description != "" {
		t.Errorf("unset optional fields = %q/%q, want empty", list[0].FixedVersion, list[0].Description)
	}
}

// TestFindingsRejectsInvalidFilters keeps the enum vocabulary in the service,
// where handlers can map ErrInvalid to a 400.
func TestFindingsRejectsInvalidFilters(t *testing.T) {
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	cases := []struct {
		name   string
		filter reports.Filter
		want   string
	}{
		{"severity", reports.Filter{Severity: "urgent"}, `severity "urgent"`},
		{"type", reports.Filter{Type: "bogus"}, `type "bogus"`},
		{"status", reports.Filter{Status: "muted"}, `status "muted"`},
		{"negative asset", reports.Filter{AssetID: -1}, "asset_id must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := service.Findings(context.Background(), tc.filter)
			if !errors.Is(err, reports.ErrInvalid) {
				t.Fatalf("Findings(%+v) error = %v, want ErrInvalid", tc.filter, err)
			}
			if list != nil {
				t.Errorf("Findings(%+v) = %+v, want nil on error", tc.filter, list)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}
