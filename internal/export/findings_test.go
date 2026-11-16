package export

import (
	"testing"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/reports"
)

// exportFindings is the fixture: one CVE in two projects (different severity
// and status), plus a rule-less secret.
func exportFindings() []reports.Finding {
	firstSeen := int64(10)
	secondSeen := int64(12)
	return []reports.Finding{
		{
			AssetID: 1, Fingerprint: "fp-alpha", Type: "vulnerability", Severity: "high",
			Title: "Shared vulnerability", RuleID: "CVE-2024-4444", PackageName: "lodash",
			PackageVersion: "4.17.0", FixedVersion: "4.17.21", Location: "package-lock.json:1",
			Status: reports.FindingStatusOpen, FirstSeenScanID: &firstSeen,
			EPSS: &epss.Score{Score: 0.2, Percentile: 0.5},
		},
		{
			AssetID: 2, Fingerprint: "fp-beta", Type: "vulnerability", Severity: "critical",
			Title: "Shared vulnerability", RuleID: "CVE-2024-4444", PackageName: "lodash",
			PackageVersion: "4.17.0", FixedVersion: "4.17.21",
			Status: reports.FindingStatusIgnored, State: "accepted_risk", Reason: "not reachable",
			ExpiresAt: "2026-12-01T00:00:00.000Z", FirstSeenScanID: &secondSeen,
			EPSS: &epss.Score{Score: 0.6, Percentile: 0.9},
		},
		{
			AssetID: 1, Fingerprint: "fp-secret", Type: "secret", Severity: "medium",
			Title: "Hardcoded token", Status: reports.FindingStatusOpen,
		},
	}
}

func cellText(t *testing.T, row []Cell, index int) string {
	t.Helper()
	if index >= len(row) {
		t.Fatalf("row has %d cells, want index %d", len(row), index)
	}
	if row[index].Number != nil {
		t.Fatalf("cell %d is numeric %v, want text", index, *row[index].Number)
	}
	return row[index].Text
}

func cellNumber(t *testing.T, row []Cell, index int) float64 {
	t.Helper()
	if index >= len(row) {
		t.Fatalf("row has %d cells, want index %d", len(row), index)
	}
	if row[index].Number == nil {
		t.Fatalf("cell %d is text %q, want a number", index, row[index].Text)
	}
	return *row[index].Number
}

func TestGroupedFoldsRulesAcrossProjects(t *testing.T) {
	names := map[int64]string{1: "Alpha", 2: "Beta"}
	table := Grouped(exportFindings(), names, true)

	if got, want := len(table.Columns), 10; got != want {
		t.Fatalf("columns = %d, want %d (with EPSS)", got, want)
	}
	if got, want := len(table.Rows), 2; got != want {
		t.Fatalf("rows = %d, want %d", got, want)
	}

	// The worst severity sorts the shared CVE first.
	shared := table.Rows[0]
	if got := cellText(t, shared, 0); got != "CVE-2024-4444" {
		t.Errorf("rule = %q", got)
	}
	if got := cellText(t, shared, 1); got != "vulnerability" {
		t.Errorf("type = %q", got)
	}
	if got := cellText(t, shared, 2); got != "critical" {
		t.Errorf("severity = %q, want the worst member's", got)
	}
	if got := cellText(t, shared, 3); got != "Shared vulnerability" {
		t.Errorf("title = %q", got)
	}
	if got := cellText(t, shared, 4); got != "lodash" {
		t.Errorf("packages = %q, want one de-duplicated name", got)
	}
	if got := cellText(t, shared, 5); got != "Alpha, Beta" {
		t.Errorf("projects = %q, want names in first-seen order", got)
	}
	if got := cellNumber(t, shared, 6); got != 2 {
		t.Errorf("findings = %v, want 2", got)
	}
	if got := cellNumber(t, shared, 7); got != 1 {
		t.Errorf("open = %v, want 1 (one member is ignored)", got)
	}
	if got := cellNumber(t, shared, 8); got != 0.6 {
		t.Errorf("max EPSS = %v, want 0.6", got)
	}
	if got := cellNumber(t, shared, 9); got != 0.9 {
		t.Errorf("max EPSS percentile = %v, want 0.9", got)
	}

	// A rule-less finding groups by fingerprint and still exports a row.
	secret := table.Rows[1]
	if got := cellText(t, secret, 0); got != "" {
		t.Errorf("rule = %q, want empty", got)
	}
	if got := cellText(t, secret, 2); got != "medium" {
		t.Errorf("severity = %q", got)
	}
}

func TestGroupedWithoutEPSSOmitsColumns(t *testing.T) {
	table := Grouped(exportFindings(), nil, false)
	if got, want := len(table.Columns), 8; got != want {
		t.Fatalf("columns = %d, want %d (no EPSS)", got, want)
	}
	if got := cellText(t, table.Rows[0], 5); got != "Asset 1, Asset 2" {
		t.Errorf("projects = %q, want id placeholders", got)
	}
}

func TestSingleWritesOneRowPerFinding(t *testing.T) {
	names := map[int64]string{1: "Alpha", 2: "Beta"}
	table := Single(exportFindings(), names, true)

	if got, want := len(table.Columns), 16; got != want {
		t.Fatalf("columns = %d, want %d (with EPSS)", got, want)
	}
	if got, want := len(table.Rows), 3; got != want {
		t.Fatalf("rows = %d, want %d", got, want)
	}

	alpha := table.Rows[0]
	checks := map[int]string{
		0: "Alpha", 1: "high", 2: "vulnerability", 3: "CVE-2024-4444",
		4: "Shared vulnerability", 5: "lodash", 6: "4.17.0", 7: "4.17.21",
		8: "package-lock.json:1", 9: "open",
	}
	for index, want := range checks {
		if got := cellText(t, alpha, index); got != want {
			t.Errorf("cell %d = %q, want %q", index, got, want)
		}
	}
	if got := cellNumber(t, alpha, 13); got != 0.2 {
		t.Errorf("EPSS = %v, want 0.2", got)
	}
	if got := cellNumber(t, alpha, 15); got != 10 {
		t.Errorf("first seen = %v, want scan 10", got)
	}

	// The ignored finding keeps its decision and expiry.
	beta := table.Rows[1]
	if got := cellText(t, beta, 9); got != "ignored" {
		t.Errorf("status = %q", got)
	}
	if got := cellText(t, beta, 10); got != "accepted_risk" {
		t.Errorf("decision = %q", got)
	}
	if got := cellText(t, beta, 11); got != "not reachable" {
		t.Errorf("reason = %q", got)
	}
	if got := cellText(t, beta, 12); got != "2026-12-01T00:00:00.000Z" {
		t.Errorf("expires_at = %q", got)
	}
}

func TestSingleWithoutEPSSKeepsFirstSeenLast(t *testing.T) {
	table := Single(exportFindings(), nil, false)
	if got, want := len(table.Columns), 14; got != want {
		t.Fatalf("columns = %d, want %d (no EPSS)", got, want)
	}
	// The last column is still first seen, now at index 13.
	if got := cellNumber(t, table.Rows[0], 13); got != 10 {
		t.Errorf("first seen = %v, want 10", got)
	}
}
