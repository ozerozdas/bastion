package reports_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
)

// TestFindingsPageAndGroupedPaging covers the service's windows: the single
// view pages in SQL with a total, the grouped view folds first and then cuts
// the page, and both reject a window the API cannot serve.
func TestFindingsPageAndGroupedPaging(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")

	criticalAlpha := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	highAlpha := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityHigh)
	secretAlpha := newFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityMedium)
	criticalBeta := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	lowBeta := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0003", findings.SeverityLow)

	seedScan(t, db, alpha.ID, "succeeded", at(10), criticalAlpha, highAlpha, secretAlpha)
	seedScan(t, db, beta.ID, "succeeded", at(11), criticalBeta, lowBeta)

	// The unpaged read still returns everything: the export and the fix plan
	// depend on it.
	all, err := service.Findings(ctx, reports.Filter{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("unpaged findings = %d, want 5", len(all))
	}

	// The second row (offset 1) starts at the beta critical, then alpha's high.
	page, total, err := service.FindingsPage(ctx, reports.Filter{}, reports.Page{Limit: 2, Offset: 1}, reports.Sort{})
	if err != nil {
		t.Fatalf("FindingsPage: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(page) != 2 {
		t.Fatalf("page = %+v, want 2 findings", page)
	}
	if page[0].AssetID != beta.ID || page[0].RuleID != "CVE-2026-0001" {
		t.Errorf("first row = %+v, want beta's critical", page[0])
	}
	if page[1].RuleID != "CVE-2026-0002" {
		t.Errorf("second row = %+v, want alpha's high", page[1])
	}

	// The last page may be short; the total does not change.
	last, total, err := service.FindingsPage(ctx, reports.Filter{}, reports.Page{Limit: 2, Offset: 4}, reports.Sort{})
	if err != nil {
		t.Fatalf("FindingsPage(last): %v", err)
	}
	if total != 5 || len(last) != 1 || last[0].RuleID != "CVE-2026-0003" {
		t.Errorf("last page = %+v (total %d), want the low finding", last, total)
	}

	// Grouped: CVE-2026-0001 folds across projects, so four groups hold five
	// findings; the page cuts groups, not findings.
	grouped, err := service.GroupedFindings(ctx, reports.Filter{}, reports.Page{Limit: 2, Offset: 1}, reports.Sort{})
	if err != nil {
		t.Fatalf("GroupedFindings: %v", err)
	}
	if grouped.Total != 4 {
		t.Errorf("grouped total = %d, want 4", grouped.Total)
	}
	if grouped.TotalFindings != 5 {
		t.Errorf("grouped total findings = %d, want 5", grouped.TotalFindings)
	}
	if len(grouped.Groups) != 2 {
		t.Fatalf("grouped page = %+v, want 2 groups", grouped.Groups)
	}
	if grouped.Groups[0].RuleID != "CVE-2026-0002" || grouped.Groups[1].RuleID != "generic-api-key" {
		t.Errorf("grouped page = %+v, want high then the secret", grouped.Groups)
	}

	// A window outside the documented bounds is refused, not clamped silently.
	for _, window := range []reports.Page{{Limit: 0}, {Limit: reports.MaxFindingLimit + 1}, {Limit: 50, Offset: -1}} {
		if _, _, err := service.FindingsPage(ctx, reports.Filter{}, window, reports.Sort{}); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("FindingsPage(%+v) error = %v, want ErrInvalid", window, err)
		}
		if _, err := service.GroupedFindings(ctx, reports.Filter{}, window, reports.Sort{}); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("GroupedFindings(%+v) error = %v, want ErrInvalid", window, err)
		}
	}
}
