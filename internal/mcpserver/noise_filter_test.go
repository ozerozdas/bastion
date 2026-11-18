package mcpserver_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/store"
)

func TestListFindingsNoiseFilters(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/noise", "acme/noise")

	build := func(kind findings.Type, rule, pkg, fixed, location string) findings.Finding {
		f := newFinding(asset.ID, kind, rule, findings.SeverityHigh, rule)
		f.PackageName, f.Ecosystem, f.FixedVersion, f.Location = pkg, "npm", fixed, location
		f.Fingerprint = findings.Fingerprint(asset.ID, f)
		return f
	}
	direct, indirect := true, false
	scanID, err := store.StartScan(context.Background(), db, asset.ID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveScanResult(context.Background(), db, scanID, store.ScanResult{
		Status:     store.ScanStatusSucceeded,
		FinishedAt: time.Now(),
		Packages: []findings.Package{
			{Ecosystem: "npm", Name: "app-dep", Version: "1.0.0", Direct: &direct},
			{Ecosystem: "npm", Name: "deep-dep", Version: "1.0.0", Direct: &indirect},
		},
		Findings: []findings.Finding{
			build(findings.TypeVulnerability, "direct-fixed", "app-dep", "2.0.0", "src/package.json"),
			build(findings.TypeVulnerability, "indirect-unfixed", "deep-dep", "", "src/package.json"),
			build(findings.TypeMisconfig, "in-tests", "", "", "app/tests/Dockerfile"),
			build(findings.TypeMisconfig, "attest-path", "", "", "src/attests/Dockerfile"),
			build(findings.TypeOutdated, "maintenance", "", "", "src/go.mod"),
		},
	}); err != nil {
		t.Fatal(err)
	}

	session := newSession(t, mcpserver.Config{Assets: newAssetsService(t, db), Reports: newReportsService(t, db)})
	cases := []struct {
		name   string
		filter map[string]any
		want   []string
	}{
		{"fix available", map[string]any{"fix": "available"}, []string{"direct-fixed"}},
		{"direct", map[string]any{"dependency": "direct"}, []string{"direct-fixed"}},
		{"indirect", map[string]any{"dependency": "indirect"}, []string{"indirect-unfixed"}},
		{"hide tests", map[string]any{"hide_tests": true}, []string{"attest-path", "direct-fixed", "indirect-unfixed", "maintenance"}},
		{"hide maintenance", map[string]any{"hide_maintenance": true}, []string{"attest-path", "direct-fixed", "in-tests", "indirect-unfixed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.filter["asset_id"] = asset.ID
			got := call[struct {
				Data struct {
					Findings []struct {
						RuleID string `json:"rule_id"`
					} `json:"findings"`
					Total int `json:"total"`
				} `json:"data"`
			}](t, session, "list_findings", tc.filter)
			rules := make([]string, 0, len(got.Data.Findings))
			for _, f := range got.Data.Findings {
				rules = append(rules, f.RuleID)
			}
			slices.Sort(rules)
			if !slices.Equal(rules, tc.want) || got.Data.Total != len(tc.want) {
				t.Fatalf("rules = %v (total %d), want %v", rules, got.Data.Total, tc.want)
			}
		})
	}
}
