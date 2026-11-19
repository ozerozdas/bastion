package reports_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// TestOWASPCategoryFor covers the 2021 mapping and the choice a finding with
// several mapped weaknesses makes.
func TestOWASPCategoryFor(t *testing.T) {
	cases := []struct {
		name string
		cwe  []string
		want string
	}{
		{name: "xss is injection", cwe: []string{"CWE-79"}, want: "A03"},
		{name: "sql injection is injection", cwe: []string{"CWE-89"}, want: "A03"},
		{name: "path traversal is access control", cwe: []string{"CWE-22"}, want: "A01"},
		{name: "broken crypto", cwe: []string{"CWE-327"}, want: "A02"},
		{name: "hard-coded credentials", cwe: []string{"CWE-798"}, want: "A07"},
		{name: "deserialization", cwe: []string{"CWE-502"}, want: "A08"},
		{name: "ssrf", cwe: []string{"CWE-918"}, want: "A10"},
		{name: "outdated component", cwe: []string{"CWE-1104"}, want: "A06"},
		{name: "missing authentication", cwe: []string{"CWE-306"}, want: "A07"},
		{name: "duplicate mapping takes the lowest category", cwe: []string{"CWE-613"}, want: "A05"},
		{name: "unknown cwe", cwe: []string{"CWE-9999"}, want: "unmapped"},
		{name: "no cwe", cwe: nil, want: "unmapped"},
		{
			name: "several cwes take the lowest category",
			cwe:  []string{"CWE-79", "CWE-22", "CWE-502"},
			want: "A01",
		},
		{name: "unknown cwes next to a known one", cwe: []string{"CWE-9999", "CWE-89"}, want: "A03"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reports.OWASPCategoryFor(tc.cwe); got != tc.want {
				t.Fatalf("OWASPCategoryFor(%v) = %q, want %q", tc.cwe, got, tc.want)
			}
		})
	}
}

// TestOWASPTop10GroupsLatestOpenFindings seeds mapped, unmapped, ignored,
// maintenance and other-asset findings and asserts every category, in order.
func TestOWASPTop10GroupsLatestOpenFindings(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/owasp-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")

	injection := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-1001", findings.SeverityHigh)
	injection.CWE = []string{"CWE-79"}
	access := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-1002", findings.SeverityCritical)
	access.CWE = []string{"CWE-79", "CWE-22"}
	sast := newFinding(alpha.ID, findings.TypeSAST, "go/sql-injection", findings.SeverityMedium)
	sast.CWE = []string{"CWE-89"}
	secret := newFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	secret.CWE = []string{"CWE-798"}
	unmapped := newFinding(alpha.ID, findings.TypeSecret, "aws-access-key", findings.SeverityLow)
	components := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-1003", findings.SeverityUnknown)
	components.CWE = []string{"CWE-1104"}
	outdated := newFinding(alpha.ID, findings.TypeOutdated, "lodash", findings.SeverityLow)
	outdated.CWE = []string{"CWE-1104"}
	ignored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-1004", findings.SeverityHigh)
	ignored.CWE = []string{"CWE-89"}

	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(11),
		injection, access, sast, secret, unmapped, components, outdated, ignored)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	betaInjection := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-1005", findings.SeverityHigh)
	betaInjection.CWE = []string{"CWE-89"}
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(10), betaInjection)

	wantOrder := []string{
		"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "unmapped",
	}
	wantAll := map[string]int{"A01": 1, "A03": 3, "A06": 1, "A07": 1, "unmapped": 1}
	wantAlpha := map[string]int{"A01": 1, "A03": 2, "A06": 1, "A07": 1, "unmapped": 1}

	for _, tc := range []struct {
		name    string
		assetID int64
		want    map[string]int
	}{
		{name: "all assets", assetID: 0, want: wantAll},
		{name: "one asset", assetID: alpha.ID, want: wantAlpha},
	} {
		t.Run(tc.name, func(t *testing.T) {
			categories, err := service.OWASPTop10(ctx, tc.assetID)
			if err != nil {
				t.Fatalf("OWASPTop10: %v", err)
			}
			if len(categories) != len(wantOrder) {
				t.Fatalf("categories = %d, want %d", len(categories), len(wantOrder))
			}
			for i, category := range categories {
				if category.ID != wantOrder[i] {
					t.Errorf("category %d = %q, want %q", i, category.ID, wantOrder[i])
				}
				if category.Title == "" || category.Findings == nil {
					t.Errorf("category %q has no title or null findings", category.ID)
				}
				if category.Count != len(category.Findings) {
					t.Errorf("category %q count = %d, findings = %d",
						category.ID, category.Count, len(category.Findings))
				}
				if got, want := category.Count, tc.want[category.ID]; got != want {
					t.Errorf("category %q count = %d, want %d", category.ID, got, want)
				}
			}
			if categories[len(categories)-1].ID != reports.OWASPUnmapped {
				t.Errorf("last category = %q, want unmapped", categories[len(categories)-1].ID)
			}
		})
	}

	if _, err := service.OWASPTop10(ctx, -1); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("negative asset id error = %v, want ErrInvalid", err)
	}
}

// TestOWASPTop10CapsCategoryFindings keeps the category count exact while the
// findings list stops at the cap and reports the truncation.
func TestOWASPTop10CapsCategoryFindings(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/owasp-cap", "Alpha")

	list := make([]findings.Finding, 0, 58)
	for i := 0; i < 55; i++ {
		finding := newFinding(alpha.ID, findings.TypeVulnerability,
			fmt.Sprintf("CVE-OWASP-CAP-%02d", i), findings.SeverityHigh)
		finding.CWE = []string{"CWE-79"} // A03 injection
		list = append(list, finding)
	}
	for i := 0; i < 3; i++ {
		finding := newFinding(alpha.ID, findings.TypeVulnerability,
			fmt.Sprintf("CVE-OWASP-ACCESS-%02d", i), findings.SeverityHigh)
		finding.CWE = []string{"CWE-22"} // A01 broken access control
		list = append(list, finding)
	}
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(11), list...)

	categories, err := service.OWASPTop10(ctx, 0)
	if err != nil {
		t.Fatalf("OWASPTop10: %v", err)
	}
	byID := make(map[string]reports.OWASPCategory, len(categories))
	for _, category := range categories {
		byID[category.ID] = category
	}

	injection := byID["A03"]
	if injection.Count != 55 {
		t.Errorf("A03 count = %d, want 55", injection.Count)
	}
	if len(injection.Findings) != reports.MaxOWASPCategoryFindings {
		t.Errorf("A03 findings = %d, want the %d cap",
			len(injection.Findings), reports.MaxOWASPCategoryFindings)
	}
	if !injection.Truncated {
		t.Error("A03 truncated = false, want true")
	}

	access := byID["A01"]
	if access.Count != 3 || len(access.Findings) != 3 || access.Truncated {
		t.Errorf("A01 = count %d, findings %d, truncated %v; want 3/3/false",
			access.Count, len(access.Findings), access.Truncated)
	}
	if empty := byID["A10"]; empty.Count != 0 || empty.Truncated {
		t.Errorf("A10 = %+v, want an empty untruncated category", empty)
	}
}
