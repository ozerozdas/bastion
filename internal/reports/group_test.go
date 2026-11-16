package reports_test

import (
	"testing"

	"github.com/ozerozdas/bastion/internal/reports"
)

// groupFinding is one member of a folded group; only the fields a test sets
// differ.
func groupFinding(assetID int64, fingerprint, ruleID, kind, severity string) reports.Finding {
	return reports.Finding{
		AssetID:     assetID,
		Fingerprint: fingerprint,
		RuleID:      ruleID,
		Type:        kind,
		Severity:    severity,
		Title:       "a finding",
		Status:      reports.FindingStatusOpen,
	}
}

// TestGroupFindingsFoldsRulesAcrossAssets covers the fold the grouped list and
// the export share: one row per rule and type, worst severity first.
func TestGroupFindingsFoldsRulesAcrossAssets(t *testing.T) {
	alpha := groupFinding(1, "fp-alpha", "CVE-2024-4444", "vulnerability", "high")
	alpha.PackageName = "lodash"
	alpha.FixedVersion = "4.17.21"
	alpha.Status = reports.FindingStatusOpen

	beta := groupFinding(2, "fp-beta", "CVE-2024-4444", "vulnerability", "critical")
	beta.PackageName = "lodash"
	beta.FixedVersion = "4.17.21"
	beta.Status = reports.FindingStatusIgnored

	secret := groupFinding(1, "fp-secret", "", "secret", "medium")

	groups := reports.GroupFindings([]reports.Finding{alpha, beta, secret})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}

	shared := groups[0]
	if shared.Key != "CVE-2024-4444\x00vulnerability" {
		t.Errorf("key = %q", shared.Key)
	}
	if shared.RuleID != "CVE-2024-4444" || shared.Severity != "critical" {
		t.Errorf("group = %+v, want the rule and its worst severity", shared)
	}
	if len(shared.Findings) != 2 || shared.ProjectCount != 2 {
		t.Errorf("group = %+v, want two members in two projects", shared)
	}
	if len(shared.AssetIDs) != 2 || shared.AssetIDs[0] != 1 || shared.AssetIDs[1] != 2 {
		t.Errorf("asset ids = %v, want first-seen order", shared.AssetIDs)
	}
	if len(shared.Packages) != 1 || shared.Packages[0] != "lodash" {
		t.Errorf("packages = %v, want one de-duplicated name", shared.Packages)
	}
	if shared.FixedVersion != "4.17.21" {
		t.Errorf("fixed version = %q, want the agreed one", shared.FixedVersion)
	}

	// A rule-less finding groups by fingerprint and keeps an empty rule id.
	if groups[1].RuleID != "" || groups[1].Key != "fp-secret\x00secret" {
		t.Errorf("rule-less group = %+v", groups[1])
	}
}

// TestGroupFindingsVaryingFixedVersions reports the disagreement instead of
// picking one member's version.
func TestGroupFindingsVaryingFixedVersions(t *testing.T) {
	first := groupFinding(1, "fp-a", "CVE-1", "vulnerability", "high")
	first.FixedVersion = "1.2.3"
	second := groupFinding(2, "fp-b", "CVE-1", "vulnerability", "high")
	second.FixedVersion = "1.4.0"

	groups := reports.GroupFindings([]reports.Finding{first, second})
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if groups[0].FixedVersion != "" {
		t.Errorf("fixed version = %q, want none when the members disagree", groups[0].FixedVersion)
	}
	if len(groups[0].FixedVersions) != 2 {
		t.Errorf("fixed versions = %v, want both", groups[0].FixedVersions)
	}
}

// TestGroupFindingsKeepsTypesApart proves a secret and a CVE with the same rule
// id are different rows.
func TestGroupFindingsKeepsTypesApart(t *testing.T) {
	groups := reports.GroupFindings([]reports.Finding{
		groupFinding(1, "fp-a", "X-1", "vulnerability", "high"),
		groupFinding(1, "fp-b", "X-1", "secret", "high"),
	})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
}

// TestGroupFindingsOrdersBySeverityThenCountThenTitle covers the order the API
// documents, which the grouped page and the export both rely on.
func TestGroupFindingsOrdersBySeverityThenCountThenTitle(t *testing.T) {
	groups := reports.GroupFindings([]reports.Finding{
		groupFinding(1, "fp-low", "LOW-1", "vulnerability", "low"),
		groupFinding(1, "fp-high-1", "HIGH-1", "vulnerability", "high"),
		groupFinding(2, "fp-high-2", "HIGH-1", "vulnerability", "high"),
		groupFinding(1, "fp-crit", "CRIT-1", "vulnerability", "critical"),
		groupFinding(1, "fp-unk", "UNK-1", "vulnerability", "unknown"),
		groupFinding(1, "fp-med", "MED-1", "vulnerability", "medium"),
	})

	got := make([]string, 0, len(groups))
	for _, group := range groups {
		got = append(got, group.RuleID)
	}
	want := []string{"CRIT-1", "HIGH-1", "MED-1", "LOW-1", "UNK-1"}
	if len(got) != len(want) {
		t.Fatalf("rule ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule ids = %v, want %v", got, want)
		}
	}
}
