package sarif_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/report/sarif"
	"github.com/ozerozdas/bastion/internal/testutil"
)

// goldenInput is the fixture shape: the tool version plus the findings a
// scanner pipeline produced. Keeping it JSON (not Go literals) makes the
// expected document easy to review beside it.
type goldenInput struct {
	ToolVersion string             `json:"tool_version"`
	Findings    []findings.Finding `json:"findings"`
}

func loadInput(t *testing.T, path string) goldenInput {
	t.Helper()
	//nolint:gosec // path is a testdata path supplied by the test.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read input %s: %v", path, err)
	}
	var in goldenInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("decode input %s: %v", path, err)
	}
	return in
}

func TestBuildGolden(t *testing.T) {
	in := loadInput(t, filepath.Join("testdata", "sarif", "basic", "input.json"))
	got := sarif.Build(in.ToolVersion, in.Findings)
	testutil.AssertJSON(t, filepath.Join("testdata", "sarif", "basic", "expected.json"), got)
}

// TestBuildShape checks the parts of SARIF 2.1.0 that GitHub code scanning
// requires and that a golden file alone would not make obvious: one run, a
// rule per unique rule id, a level and message per result, rule references
// that exist, and repository-relative locations.
func TestBuildShape(t *testing.T) {
	in := loadInput(t, filepath.Join("testdata", "sarif", "basic", "input.json"))
	report := sarif.Build(in.ToolVersion, in.Findings)

	if report.Schema != sarif.SchemaURI || report.Version != sarif.Version {
		t.Fatalf("header = %q/%q, want %q/%q", report.Schema, report.Version, sarif.SchemaURI, sarif.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(report.Runs))
	}
	run := report.Runs[0]
	if run.Tool.Driver.Name != sarif.ToolName || run.Tool.Driver.Version != in.ToolVersion {
		t.Fatalf("driver = %+v, want %s@%s", run.Tool.Driver, sarif.ToolName, in.ToolVersion)
	}

	ruleIDs := make(map[string]bool, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == "" || rule.ShortDescription.Text == "" {
			t.Fatalf("rule %+v is missing an id or description", rule)
		}
		if ruleIDs[rule.ID] {
			t.Fatalf("rule %q appears twice", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}

	if len(run.Results) != len(in.Findings) {
		t.Fatalf("results = %d, want one per finding (%d)", len(run.Results), len(in.Findings))
	}
	for i, result := range run.Results {
		f := in.Findings[i]
		if result.Level != wantLevel(f.Severity) {
			t.Errorf("result %d level = %q, want %q", i, result.Level, wantLevel(f.Severity))
		}
		if result.Message.Text == "" {
			t.Errorf("result %d has no message text", i)
		}
		if result.RuleID != "" && !ruleIDs[result.RuleID] {
			t.Errorf("result %d references unknown rule %q", i, result.RuleID)
		}
		if result.PartialFingerprints[sarif.FingerprintKey] != f.Fingerprint {
			t.Errorf("result %d fingerprint = %q, want %q", i, result.PartialFingerprints[sarif.FingerprintKey], f.Fingerprint)
		}
		for _, location := range result.Locations {
			uri := location.PhysicalLocation.ArtifactLocation.URI
			if uri == "" || strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "./") {
				t.Errorf("result %d uri = %q, want a repository-relative path", i, uri)
			}
			if region := location.PhysicalLocation.Region; region != nil && region.StartLine < 1 {
				t.Errorf("result %d startLine = %d, want at least 1", i, region.StartLine)
			}
		}
	}
}

func wantLevel(severity findings.Severity) string {
	switch severity {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// TestBuildEmpty keeps the document valid for a clean scan: GitHub accepts a
// run without results, so the header and driver must still be present.
func TestBuildEmpty(t *testing.T) {
	report := sarif.Build("dev", nil)
	if len(report.Runs) != 1 || report.Runs[0].Tool.Driver.Name != sarif.ToolName {
		t.Fatalf("report = %+v, want one run with the bastion driver", report)
	}
	if len(report.Runs[0].Results) != 0 {
		t.Fatalf("results = %d, want 0", len(report.Runs[0].Results))
	}
}
