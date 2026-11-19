package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// seedTriggeredScan persists one finished scan with an explicit trigger and
// started_at, plus one succeeded scanner run.
func seedTriggeredScan(t *testing.T, db *sql.DB, assetID int64, trigger, status string,
	started, finished time.Time, list ...findings.Finding) int64 {
	t.Helper()

	scanID, err := store.StartScan(context.Background(), db, assetID, trigger)
	if err != nil {
		t.Fatalf("StartScan(asset %d): %v", assetID, err)
	}
	if err := store.SaveScanResult(context.Background(), db, scanID, store.ScanResult{
		Status:     status,
		FinishedAt: finished,
		ScannerRuns: []store.ScannerRun{
			{Scanner: "trivy", Status: store.ScanStatusSucceeded},
		},
		Findings: list,
	}); err != nil {
		t.Fatalf("SaveScanResult(scan %d): %v", scanID, err)
	}
	if _, err := db.ExecContext(context.Background(),
		`UPDATE scans SET started_at = ? WHERE id = ?`,
		started.UTC().Format(time.RFC3339), scanID); err != nil {
		t.Fatalf("set started_at of scan %d: %v", scanID, err)
	}
	return scanID
}

// TestCIHistoryFiltersOrdersAndValidates seeds CLI, API, UI and archived scans
// plus a queued CLI scan, then asserts the trigger filter, newest-first order,
// the raw counts and the limit validation.
func TestCIHistoryFiltersOrdersAndValidates(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/ci-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/ci-beta", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/ci-archived", "Archived")

	critical := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-CI-1", findings.SeverityCritical)
	ignoredHigh := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-CI-2", findings.SeverityHigh)
	cliScan := seedTriggeredScan(t, db, alpha.ID, store.ScanTriggerCLI, store.ScanStatusSucceeded,
		at(10), at(10).Add(90*time.Second), critical, ignoredHigh)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignoredHigh.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	apiScan := seedTriggeredScan(t, db, beta.ID, store.ScanTriggerAPI, store.ScanStatusSucceeded,
		at(11), at(11),
		newFinding(beta.ID, findings.TypeVulnerability, "CVE-CI-3", findings.SeverityMedium))

	// A UI scan and an archived asset's CLI scan are out of scope.
	seedTriggeredScan(t, db, alpha.ID, "ui", store.ScanStatusSucceeded, at(12), at(12),
		newFinding(alpha.ID, findings.TypeVulnerability, "CVE-CI-4", findings.SeverityCritical))
	seedTriggeredScan(t, db, archived.ID, store.ScanTriggerCLI, store.ScanStatusSucceeded,
		at(13), at(13),
		newFinding(archived.ID, findings.TypeVulnerability, "CVE-CI-5", findings.SeverityCritical))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(14).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	// A queued CLI scan is the newest run, without a start or finish time.
	queued, err := store.StartScan(ctx, db, alpha.ID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan(queued): %v", err)
	}

	report, err := service.CIHistory(ctx, 0, reports.DefaultCIHistoryLimit)
	if err != nil {
		t.Fatalf("CIHistory: %v", err)
	}
	if len(report.Runs) != 3 {
		t.Fatalf("runs = %+v, want the queued, API and CLI runs", report.Runs)
	}
	if report.Runs[0].ScanID != queued || report.Runs[0].DurationMS != nil ||
		report.Runs[0].StartedAt != nil || report.Runs[0].FinishedAt != nil {
		t.Errorf("newest run = %+v, want the queued scan without times", report.Runs[0])
	}
	if len(report.Runs[0].Scanners) != 0 {
		t.Errorf("queued scanners = %+v, want none", report.Runs[0].Scanners)
	}

	apiRun := report.Runs[1]
	if apiRun.ScanID != apiScan || apiRun.Trigger != store.ScanTriggerAPI ||
		apiRun.AssetID != beta.ID || apiRun.DisplayName != "Beta" {
		t.Errorf("second run = %+v, want the beta API scan", apiRun)
	}
	if apiRun.DurationMS == nil || *apiRun.DurationMS != 0 {
		t.Errorf("api duration = %v, want 0", apiRun.DurationMS)
	}
	if apiRun.Counts.Medium != 1 || apiRun.Counts.Critical != 0 {
		t.Errorf("api counts = %+v, want one medium", apiRun.Counts)
	}
	if len(apiRun.Scanners) != 1 || apiRun.Scanners[0].Scanner != "trivy" ||
		apiRun.Scanners[0].Status != store.ScanStatusSucceeded {
		t.Errorf("api scanners = %+v, want trivy succeeded", apiRun.Scanners)
	}

	cliRun := report.Runs[2]
	if cliRun.ScanID != cliScan || cliRun.Trigger != store.ScanTriggerCLI {
		t.Errorf("third run = %+v, want the alpha CLI scan", cliRun)
	}
	if cliRun.DurationMS == nil || *cliRun.DurationMS != 90000 {
		t.Errorf("cli duration = %v, want 90000", cliRun.DurationMS)
	}
	// The ignored high finding still counts: the history is not ignore-filtered.
	if cliRun.Counts.Critical != 1 || cliRun.Counts.High != 1 {
		t.Errorf("cli counts = %+v, want 1 critical and 1 high", cliRun.Counts)
	}

	scoped, err := service.CIHistory(ctx, alpha.ID, reports.DefaultCIHistoryLimit)
	if err != nil {
		t.Fatalf("CIHistory(alpha): %v", err)
	}
	if len(scoped.Runs) != 2 || scoped.Runs[0].ScanID != queued || scoped.Runs[1].ScanID != cliScan {
		t.Errorf("scoped runs = %+v, want alpha's queued and CLI scans", scoped.Runs)
	}

	limited, err := service.CIHistory(ctx, 0, 1)
	if err != nil {
		t.Fatalf("CIHistory(limit=1): %v", err)
	}
	if len(limited.Runs) != 1 || limited.Runs[0].ScanID != queued {
		t.Errorf("limited runs = %+v, want only the newest", limited.Runs)
	}

	for _, limit := range []int{-1, 0, reports.MaxCIHistoryLimit + 1} {
		if _, err := service.CIHistory(ctx, 0, limit); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("CIHistory(limit=%d) error = %v, want ErrInvalid", limit, err)
		}
	}
	if _, err := service.CIHistory(ctx, -1, 50); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("CIHistory(asset=-1) error = %v, want ErrInvalid", err)
	}
}
