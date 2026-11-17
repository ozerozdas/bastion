package reports_test

import (
	"context"
	"errors"
	"strings"
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

// TestFindingsSearch covers the q filter (#148): the same substring is matched
// against title, rule id, package name and file path, case-insensitively, in
// the list, its count and the grouped view. LIKE wildcards in the query are
// literal text, so a search for "%" finds the percent sign, not every row.
func TestFindingsSearch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")

	alphaVuln := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	alphaVuln.Title = "Remote code execution in lodash"
	alphaVuln.PackageName = "lodash"
	alphaVuln.Location = "package-lock.json:1"
	alphaSecret := newFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	alphaSecret.Title = "Generic API key"
	alphaSecret.Location = ".env:4"

	betaVuln := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	betaVuln.Title = "Remote code execution in lodash"
	betaVuln.PackageName = "lodash"
	betaVuln.Location = "go.sum:2"
	betaOdd := newFinding(beta.ID, findings.TypeMisconfig, "CUSTOM-1", findings.SeverityLow)
	betaOdd.Title = "Coverage 100% of unsafe_test"
	betaOdd.Location = "src/foo_bar.go:9"

	seedScan(t, db, alpha.ID, "succeeded", at(10), alphaVuln, alphaSecret)
	seedScan(t, db, beta.ID, "succeeded", at(11), betaVuln, betaOdd)

	cases := []struct {
		name  string
		query string
		want  int // findings; the two CVE-2026-0001 rows are one group
	}{
		{"cve id", "cve-2026-0001", 2},
		{"package, upper case", "LODASH", 2},
		{"title", "REMOTE CODE", 2},
		{"rule id", "generic-api-key", 1},
		{"file path", "package-lock", 1},
		{"trimmed", "  lodash  ", 2},
		{"literal percent", "100%", 1},
		{"literal underscore", "unsafe_test", 1},
		{"wildcard percent is not a wildcard", "%", 1},
		{"wildcard underscore is not a wildcard", "_", 1},
		{"no match", "no-such-finding", 0},
		{"empty means no filter", "", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := service.Findings(ctx, reports.Filter{Query: tc.query})
			if err != nil {
				t.Fatalf("Findings(%q): %v", tc.query, err)
			}
			if len(list) != tc.want {
				t.Fatalf("Findings(%q) = %d rows, want %d", tc.query, len(list), tc.want)
			}

			page, total, err := service.FindingsPage(ctx, reports.Filter{Query: tc.query},
				reports.Page{Limit: reports.DefaultFindingLimit}, reports.Sort{})
			if err != nil {
				t.Fatalf("FindingsPage(%q): %v", tc.query, err)
			}
			if total != tc.want || len(page) != tc.want {
				t.Errorf("FindingsPage(%q) = %d rows (total %d), want %d", tc.query, len(page), total, tc.want)
			}

			grouped, err := service.GroupedFindings(ctx, reports.Filter{Query: tc.query},
				reports.Page{Limit: reports.DefaultFindingLimit}, reports.Sort{})
			if err != nil {
				t.Fatalf("GroupedFindings(%q): %v", tc.query, err)
			}
			if grouped.TotalFindings != tc.want {
				t.Errorf("GroupedFindings(%q) total findings = %d, want %d", tc.query, grouped.TotalFindings, tc.want)
			}
		})
	}

	// The two CVE-2026-0001 findings fold into one group, so the group count
	// narrows with the search too.
	grouped, err := service.GroupedFindings(ctx, reports.Filter{Query: "lodash"},
		reports.Page{Limit: reports.DefaultFindingLimit}, reports.Sort{})
	if err != nil {
		t.Fatalf("GroupedFindings(lodash): %v", err)
	}
	if grouped.Total != 1 || len(grouped.Groups) != 1 || grouped.Groups[0].RuleID != "CVE-2026-0001" {
		t.Errorf("grouped lodash = %+v, want the one CVE group", grouped)
	}

	// A query beyond the cap is refused with ErrInvalid, not silently cut.
	if _, err := service.Findings(ctx, reports.Filter{Query: strings.Repeat("a", reports.MaxQueryLength+1)}); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("oversized query error = %v, want ErrInvalid", err)
	}
}
