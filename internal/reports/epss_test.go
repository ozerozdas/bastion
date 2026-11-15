package reports_test

import (
	"context"
	"testing"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
)

// fakeEPSS is a map-backed EPSSLookup; the real service is tested in its own
// package, so this only proves the read-time join.
type fakeEPSS map[string]epss.Score

func (f fakeEPSS) Lookup(cve string) (epss.Score, bool) {
	score, ok := f[cve]
	return score, ok
}

func TestFindingsAndFixPlanCarryEPSS(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/epss", "epss")

	log4j := newFinding(asset.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical)
	log4j.PackageVersion = "2.14.0"
	log4j.FixedVersion = "2.17.0"
	minor := newFinding(asset.ID, findings.TypeVulnerability, "CVE-2022-0001", findings.SeverityHigh)
	minor.PackageVersion = "2.14.0"
	minor.FixedVersion = "2.17.1"
	seedScan(t, db, asset.ID, "succeeded", at(12), log4j, minor)

	service, err := reports.NewService(db, reports.WithEPSS(fakeEPSS{
		"CVE-2021-44228": {Score: 0.99999, Percentile: 1.0},
		"CVE-2022-0001":  {Score: 0.00042, Percentile: 0.1},
	}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	list, err := service.Findings(context.Background(), reports.Filter{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("findings = %d, want 2", len(list))
	}
	for _, finding := range list {
		if finding.EPSS == nil {
			t.Fatalf("finding %s has no EPSS score", finding.RuleID)
		}
		if finding.RuleID == "CVE-2021-44228" && finding.EPSS.Score != 0.99999 {
			t.Errorf("log4j score = %v, want 0.99999", finding.EPSS.Score)
		}
	}

	plan, err := service.FixPlan(context.Background(), asset.ID)
	if err != nil {
		t.Fatalf("FixPlan: %v", err)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(plan.Steps))
	}
	highest := plan.Steps[0].MaxEPSS
	if highest == nil {
		t.Fatal("step has no MaxEPSS")
	}
	if highest.Score != 0.99999 || highest.Percentile != 1.0 {
		t.Errorf("MaxEPSS = %+v, want the highest score", highest)
	}
}

func TestFindingsWithoutLookupHaveNoEPSS(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/no-epss", "no-epss")
	seedScan(t, db, asset.ID, "succeeded", at(12),
		newFinding(asset.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical))

	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	list, err := service.Findings(context.Background(), reports.Filter{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if list[0].EPSS != nil {
		t.Errorf("EPSS = %+v, want nil without a lookup", list[0].EPSS)
	}
}
