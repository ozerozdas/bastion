package render_test

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/report/render"
	"github.com/ozerozdas/bastion/internal/reports"
)

var update = flag.Bool("update", false, "update golden files")

// fixture is one pinned snapshot with every section populated. The decision
// reason carries a pipe, markup and a newline, so the goldens prove each
// renderer neutralises them.
func fixture() reports.Snapshot {
	generated := time.Date(2026, 11, 27, 9, 30, 0, 0, time.UTC)
	started := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 11, 27, 9, 20, 0, 0, time.UTC)
	expires := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	firstSeen := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	duration := int64(1200)
	mean := 12.5

	return reports.Snapshot{
		GeneratedAt: generated,
		Scope:       reports.SnapshotScope{All: true},
		Coverage: reports.SnapshotCoverage{
			AssetsTotal:  2,
			Scanned:      1,
			NeverScanned: 1,
			Assets: []reports.SnapshotAssetCoverage{
				{
					AssetID:     1,
					DisplayName: "Alpha | repo",
					Kind:        "repo",
					Ref:         "octo/alpha",
					LastScan: &reports.SnapshotLastScan{
						ID:         7,
						Status:     "succeeded",
						StartedAt:  &started,
						FinishedAt: &finished,
					},
					Scanners: []reports.SnapshotScannerRun{
						{
							Name:       "trivy",
							Version:    "0.60.0",
							DBVersion:  "2026-11-01",
							Status:     "succeeded",
							DurationMS: &duration,
						},
						{Name: "gitleaks", Status: "failed", Error: "config missing"},
					},
				},
				{
					AssetID:     2,
					DisplayName: "Beta",
					Kind:        "path",
					Ref:         "/srv/beta",
					Scanners:    []reports.SnapshotScannerRun{},
				},
			},
		},
		Findings: reports.SnapshotFindings{
			Total: reports.SeverityTotals{Critical: 1, High: 1, Low: 1},
			Open:  3,
			Assets: []reports.SnapshotAssetFindings{
				{
					AssetID:     1,
					DisplayName: "Alpha | repo",
					Kind:        "repo",
					Total:       2,
					Severity:    reports.SeverityTotals{Critical: 1, High: 1},
				},
				{
					AssetID:     2,
					DisplayName: "Beta",
					Kind:        "path",
					Total:       1,
					Severity:    reports.SeverityTotals{Low: 1},
				},
			},
		},
		SLA: reports.SnapshotSLA{
			Thresholds:        reports.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180},
			WindowDays:        90,
			OpenCount:         3,
			OverdueCount:      1,
			FixedInWindow:     2,
			MeanTimeToFixDays: &mean,
			Overdue: []reports.SnapshotOverdue{
				{
					AssetID:       1,
					AssetName:     "Alpha | repo",
					FindingID:     11,
					Fingerprint:   "fp-critical",
					Type:          "vulnerability",
					Severity:      "critical",
					Title:         "CVE-2026-0001 | remote code",
					RuleID:        "CVE-2026-0001",
					PackageName:   "openssl",
					Location:      "go.mod",
					FirstSeen:     firstSeen,
					AgeDays:       87,
					ThresholdDays: 7,
					OverdueDays:   80,
				},
			},
		},
		Decisions: reports.SnapshotDecisions{
			Total:   2,
			Expired: 1,
			ByState: []reports.SnapshotDecisionCount{
				{Key: "ignored", Count: 1},
				{Key: "accepted_risk", Count: 1},
				{Key: "false_positive", Count: 0},
			},
			ByDecidedBy: []reports.SnapshotDecisionCount{
				{Key: "user", Count: 1},
				{Key: "agent", Count: 1},
			},
			Entries: []reports.SnapshotDecision{
				{
					AssetID:     1,
					AssetName:   "Alpha | repo",
					Fingerprint: "fp-high",
					Type:        "misconfig",
					RuleID:      "CKV_AWS_1",
					Title:       "S3 bucket public",
					PackageName: "aws",
					Location:    "main.tf",
					Severity:    "high",
					State:       "accepted_risk",
					Reason:      "GPL | needs <script>review\nsecond line",
					DecidedBy:   "agent",
					ExpiresAt:   &expires,
					Expired:     true,
					CreatedAt:   time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC),
				},
				{
					AssetID:     2,
					AssetName:   "Beta",
					Fingerprint: "fp-low",
					Type:        "outdated",
					RuleID:      "lodash",
					Title:       "lodash outdated",
					Severity:    "low",
					State:       "ignored",
					Reason:      "not deployed",
					DecidedBy:   "user",
					CreatedAt:   time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC),
				},
			},
		},
		SuppressionRules: reports.SnapshotSuppressionRules{
			ActiveCount:   1,
			ProposedCount: 1,
			Rules: []reports.SnapshotRule{
				{
					ID:          5,
					AssetID:     ptr(int64(1)),
					AssetName:   "Alpha | repo",
					FindingType: "vulnerability",
					RuleID:      "CVE-2099-9999",
					PackageName: "openssl",
					PathGlob:    "**/*.mod",
					State:       "ignored",
					Reason:      "not deployed",
					ExpiresAt:   &expires,
					Expired:     true,
					CreatedBy:   "user",
					CreatedAt:   time.Date(2026, 9, 2, 7, 0, 0, 0, time.UTC),
					Matched:     2,
				},
			},
		},
		LicencePolicy: reports.SnapshotLicencePolicy{
			Global: reports.SnapshotPolicy{
				Allow: []string{"BSD-3-Clause"},
				Deny:  []string{"GPL-3.0", "AGPL-3.0"},
			},
			Assets: []reports.SnapshotAssetPolicy{
				{
					AssetID:   1,
					AssetName: "Alpha | repo",
					Allow:     []string{"MIT"},
					Deny:      []string{"GPL-3.0"},
				},
			},
		},
	}
}

// TestGolden renders the full fixture in all three formats and compares the
// bytes with the checked-in documents; run with -update to rewrite them.
func TestGolden(t *testing.T) {
	snapshot := fixture()
	cases := []struct {
		name   string
		file   string
		render func(io.Writer, reports.Snapshot) error
	}{
		{name: "json", file: "snapshot.json", render: render.JSON},
		{name: "markdown", file: "snapshot.md", render: render.Markdown},
		{name: "html", file: "snapshot.html", render: render.HTML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tc.render(&out, snapshot); err != nil {
				t.Fatalf("render: %v", err)
			}
			assertGolden(t, filepath.Join("testdata", tc.file), out.Bytes())
		})
	}
}

// TestHTMLSelfContained proves the page is offline and safe: html/template
// escapes the hostile cell, so no script survives and no remote URL appears.
func TestHTMLSelfContained(t *testing.T) {
	var out bytes.Buffer
	if err := render.HTML(&out, fixture()); err != nil {
		t.Fatalf("render html: %v", err)
	}
	document := out.String()

	if strings.Contains(document, "<script") {
		t.Error("document contains a script element")
	}
	for _, scheme := range []string{"http://", "https://"} {
		if strings.Contains(document, scheme) {
			t.Errorf("document references %s", scheme)
		}
	}
	if !strings.Contains(document, "&lt;script&gt;") {
		t.Error("hostile cell was not escaped")
	}
	if strings.Contains(document, "<style src") || strings.Contains(document, "<link") {
		t.Error("document loads an external stylesheet")
	}
}

// TestEmpty keeps every section present and short when the snapshot has no
// data, for both document formats.
func TestEmpty(t *testing.T) {
	empty := reports.Snapshot{}
	cases := []struct {
		name   string
		render func(io.Writer, reports.Snapshot) error
	}{
		{name: "markdown", render: render.Markdown},
		{name: "html", render: render.HTML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tc.render(&out, empty); err != nil {
				t.Fatalf("render: %v", err)
			}
			document := out.String()
			for _, heading := range []string{
				"Bastion security report",
				"Coverage",
				"Open findings",
				"SLA",
				"Triage decisions",
				"Suppression rules",
				"Licence policy",
			} {
				if !strings.Contains(document, heading) {
					t.Errorf("document lacks %q", heading)
				}
			}
			if got := strings.Count(document, "None."); got != 6 {
				t.Errorf(`"None." count = %d, want 6`, got)
			}
			if strings.Contains(document, "--- |") {
				t.Error("empty document renders a table")
			}
			if !strings.Contains(document, "—") {
				t.Error("empty document does not mark the missing timestamp")
			}
		})
	}
}

// TestMarkdownInlineInjection proves a data value outside a table cannot open a
// heading or list: its newlines collapse to spaces and a leading marker is
// escaped.
func TestMarkdownInlineInjection(t *testing.T) {
	injected := "\n# injected\n- item"
	snapshot := reports.Snapshot{
		Scope: reports.SnapshotScope{AssetID: ptr(int64(1)), AssetName: injected},
		LicencePolicy: reports.SnapshotLicencePolicy{
			Global: reports.SnapshotPolicy{Allow: []string{injected}},
		},
	}

	var out bytes.Buffer
	if err := render.Markdown(&out, snapshot); err != nil {
		t.Fatalf("render markdown: %v", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "# injected") || strings.HasPrefix(line, "- item") {
			t.Errorf("line %q starts a block from injected data", line)
		}
	}
}

// assertGolden writes got to path with -update, otherwise compares bytes.
func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	//nolint:gosec // path is a testdata path supplied by the test.
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden %s mismatch\n--- got ---\n%s--- want ---\n%s", path, got, want)
	}
}

// ptr returns a pointer to value, for the snapshot's nullable fields.
func ptr[T any](value T) *T {
	return &value
}
