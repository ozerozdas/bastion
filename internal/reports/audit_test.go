package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// auditSeverity spreads 501 findings over the severity scale: 2 critical, 3
// high, 4 medium, 5 low and 487 unknown.
func auditSeverity(index int) findings.Severity {
	switch {
	case index < 2:
		return findings.SeverityCritical
	case index < 5:
		return findings.SeverityHigh
	case index < 9:
		return findings.SeverityMedium
	case index < 14:
		return findings.SeverityLow
	default:
		return findings.SeverityUnknown
	}
}

// TestAuditSummarizesTruncatesAndComposesFixPlan seeds more findings than the
// cap plus an ignored and an archived one, then asserts the summary counts
// everything in scope, the findings list is capped, and the fix plan is only
// built for an asset.
func TestAuditSummarizesTruncatesAndComposesFixPlan(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/audit-alpha", "Alpha")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/audit-archived", "Archived")

	list := make([]findings.Finding, 0, 502)
	for i := 0; i < 501; i++ {
		finding := newFinding(alpha.ID, findings.TypeVulnerability,
			fmt.Sprintf("CVE-AUDIT-%04d", i), auditSeverity(i))
		if i < 2 {
			// The two critical findings share a package, so the fix plan has one
			// step that closes both.
			finding.PackageVersion = "1.0.0"
			finding.FixedVersion = "1.2.0"
		}
		list = append(list, finding)
	}
	ignored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-AUDIT-IGNORED", findings.SeverityCritical)
	list = append(list, ignored)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(10), list...)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(10),
		newFinding(archived.ID, findings.TypeVulnerability, "CVE-AUDIT-ARCHIVED", findings.SeverityCritical))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(11).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	report, err := service.Audit(ctx, alpha.ID)
	if err != nil {
		t.Fatalf("Audit(alpha): %v", err)
	}
	if report.Asset == nil || report.Asset.ID != alpha.ID ||
		report.Asset.DisplayName != "Alpha" || report.Asset.Kind != string(findings.AssetKindPath) {
		t.Errorf("asset = %+v, want alpha", report.Asset)
	}
	wantSummary := reports.AuditSummary{
		Critical: 2, High: 3, Medium: 4, Low: 5, Unknown: 487, Total: 501,
	}
	if report.Summary != wantSummary {
		t.Errorf("summary = %+v, want %+v", report.Summary, wantSummary)
	}
	if !report.Truncated {
		t.Errorf("truncated = false, want true")
	}
	if len(report.Findings) != reports.MaxAuditFindings {
		t.Errorf("findings = %d, want the %d-entry cap", len(report.Findings), reports.MaxAuditFindings)
	}
	if len(report.Findings) > 0 && report.Findings[0].Severity != string(findings.SeverityCritical) {
		t.Errorf("first finding severity = %q, want critical", report.Findings[0].Severity)
	}
	if len(report.FixPlan.Steps) != 1 || report.FixPlan.Steps[0].FindingCount != 2 {
		t.Errorf("fix plan steps = %+v, want one step closing two findings", report.FixPlan.Steps)
	}

	// The fleet pack has no asset and no fix plan, but the same summary:
	// archived assets are out of scope.
	fleet, err := service.Audit(ctx, 0)
	if err != nil {
		t.Fatalf("Audit(fleet): %v", err)
	}
	if fleet.Asset != nil {
		t.Errorf("fleet asset = %+v, want nil", fleet.Asset)
	}
	if fleet.Summary != wantSummary || !fleet.Truncated || len(fleet.Findings) != reports.MaxAuditFindings {
		t.Errorf("fleet pack = %+v, want the same summary and cap", fleet)
	}
	if len(fleet.FixPlan.Steps) != 0 || len(fleet.FixPlan.NoFix) != 0 {
		t.Errorf("fleet fix plan = %+v, want empty", fleet.FixPlan)
	}

	if _, err := service.Audit(ctx, 424242); !errors.Is(err, reports.ErrNotFound) {
		t.Errorf("Audit(unknown) error = %v, want ErrNotFound", err)
	}
	if _, err := service.Audit(ctx, -1); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("Audit(-1) error = %v, want ErrInvalid", err)
	}
}
