package gitleaks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/testutil"
)

func TestNormalizeGolden(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "gitleaks", "*", "input.json"))
	if err != nil {
		t.Fatalf("glob cases: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatal("no testdata/gitleaks cases found")
	}

	for _, input := range inputs {
		dir := filepath.Dir(input)
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			//nolint:gosec // input is a testdata path from filepath.Glob.
			raw, err := os.ReadFile(input)
			if err != nil {
				t.Fatalf("read input: %v", err)
			}
			asset := findings.Asset{
				ID:          1,
				Kind:        findings.AssetKindPath,
				DisplayName: name,
				Ref:         filepath.ToSlash(filepath.Join("testdata", "gitleaks", name)),
			}
			fs, pkgs, err := New().Normalize(&scanners.RawResult{
				Scanner: "gitleaks",
				Version: Version,
				Raw:     raw,
			}, asset)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			// The scan pipeline merges findings that share a fingerprint
			// (PROJECT_SPEC.md §5); the goldens show that merged output.
			fs = findings.Merge(fs)
			testutil.AssertJSON(t, filepath.Join(dir, "expected.json"), struct {
				Findings []findings.Finding `json:"findings"`
				Packages []findings.Package `json:"packages"`
			}{Findings: fs, Packages: pkgs})
		})
	}
}
