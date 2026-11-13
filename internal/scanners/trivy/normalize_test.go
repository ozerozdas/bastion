package trivy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/testutil"
)

func TestNormalizeGolden(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "trivy", "*", "input.json"))
	if err != nil {
		t.Fatalf("glob cases: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatal("no testdata/trivy cases found")
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
				Ref:         filepath.ToSlash(filepath.Join("testdata", "trivy", name)),
			}
			fs, pkgs, err := New().Normalize(&scanners.RawResult{
				Scanner: "trivy",
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

func TestMaxCVSSIsDeterministic(t *testing.T) {
	tests := []struct {
		name   string
		scores map[string]cvssScore
		want   *float64
	}{
		{
			name:   "highest v3 wins regardless of map order",
			scores: map[string]cvssScore{"nvd": {V3Score: 5.3}, "redhat": {V3Score: 7.5}, "ghsa": {V3Score: 6.1}},
			want:   ptr(7.5),
		},
		{
			name:   "v3 preferred over a higher v2",
			scores: map[string]cvssScore{"nvd": {V2Score: 9.0}, "redhat": {V3Score: 7.5}},
			want:   ptr(7.5),
		},
		{
			name:   "v2 fallback when no source has v3",
			scores: map[string]cvssScore{"nvd": {V2Score: 4.3}, "redhat": {V2Score: 6.5}},
			want:   ptr(6.5),
		},
		{
			name:   "zero scores are not a value",
			scores: map[string]cvssScore{"nvd": {}, "redhat": {V3Score: 0}},
			want:   nil,
		},
		{
			name:   "no sources",
			scores: map[string]cvssScore{},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 20; i++ { // map iteration order varies between runs
				got := maxCVSS(tt.scores)
				switch {
				case tt.want == nil && got != nil:
					t.Fatalf("maxCVSS = %v, want nil", *got)
				case tt.want != nil && got == nil:
					t.Fatalf("maxCVSS = nil, want %v", *tt.want)
				case tt.want != nil && *got != *tt.want:
					t.Fatalf("maxCVSS = %v, want %v", *got, *tt.want)
				}
			}
		})
	}
}

func ptr(v float64) *float64 { return &v }

func TestNormalizeLicenseVersionIgnoresTargetPath(t *testing.T) {
	// The license entry is reported under "LICENSES/npm.txt" while the package
	// inventory lives under "package-lock.json". The version must still be
	// found: the lookup is keyed by package name, never by target path.
	input := `{
		"SchemaVersion": 2,
		"Results": [
			{
				"Target": "package-lock.json",
				"Class": "lang-pkgs",
				"Type": "npm",
				"Packages": [{"Name": "gpl-fixture", "Version": "1.0.0"}]
			},
			{
				"Target": "LICENSES/npm.txt",
				"Class": "license",
				"Licenses": [{"Severity": "HIGH", "Category": "restricted", "PkgName": "gpl-fixture", "FilePath": "LICENSES/npm.txt", "Name": "GPL-3.0-only"}]
			}
		]
	}`
	fs, _, err := New().Normalize(&scanners.RawResult{Raw: []byte(input)}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	if fs[0].Type != findings.TypeLicense {
		t.Fatalf("type = %q, want license", fs[0].Type)
	}
	if fs[0].PackageVersion != "1.0.0" {
		t.Fatalf("package_version = %q, want 1.0.0", fs[0].PackageVersion)
	}
	if fs[0].Location != "LICENSES/npm.txt" {
		t.Fatalf("location = %q, want LICENSES/npm.txt", fs[0].Location)
	}
}

func TestVulnerabilityAliases(t *testing.T) {
	v := vuln{
		VulnerabilityID: "cve-2021-23337",
		VendorIDs:       []string{"ghsa-35jh-r3h4-6jhm", "CVE-2021-23337"},
		PrimaryURL:      "https://avd.aquasec.com/nvd/cve-2021-23337",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
			// A reference may point at a related advisory; it is not an alias.
			"https://github.com/advisories/GHSA-dddd-eeee-ffff",
		},
	}
	want := []string{"CVE-2021-23337", "GHSA-35JH-R3H4-6JHM"}
	if got := vulnerabilityAliases(v); !slices.Equal(got, want) {
		t.Fatalf("aliases = %v, want %v", got, want)
	}

	// Without a vendor id only the primary id remains: references do not add
	// ids, however many advisory URLs they contain.
	v.VendorIDs = nil
	if got := vulnerabilityAliases(v); !slices.Equal(got, []string{"CVE-2021-23337"}) {
		t.Fatalf("aliases without vendor ids = %v, want only the primary id", got)
	}
}

func TestVulnerabilityAliasesMergeWithOSV(t *testing.T) {
	// Trivy reports the CVE and names the GHSA as a vendor id; OSV reports the
	// GHSA and lists the CVE in its own aliases. The pair must become one
	// finding, with Trivy's fingerprint.
	input := `{
		"SchemaVersion": 2,
		"Results": [{
			"Target": "package-lock.json",
			"Class": "lang-pkgs",
			"Type": "npm",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2021-23337",
				"VendorIDs": ["GHSA-35jh-r3h4-6jhm"],
				"PkgName": "lodash",
				"InstalledVersion": "4.17.20",
				"Title": "Command injection in lodash",
				"Severity": "HIGH"
			}]
		}]
	}`
	fs, _, err := New().Normalize(&scanners.RawResult{Raw: []byte(input)}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	trivyFinding := fs[0]

	osvFinding := findings.Finding{
		AssetID:        1,
		Type:           findings.TypeVulnerability,
		RuleID:         "GHSA-35JH-R3H4-6JHM",
		Severity:       findings.SeverityHigh,
		Title:          "Command injection in lodash",
		PackageName:    "lodash",
		PackageVersion: "4.17.20",
		Ecosystem:      "npm",
		Location:       "package-lock.json",
		Scanner:        "osv",
		Aliases:        []string{"CVE-2021-23337"},
	}
	osvFinding.Fingerprint = findings.Fingerprint(osvFinding.AssetID, osvFinding)

	got := findings.Merge([]findings.Finding{trivyFinding, osvFinding})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Fingerprint != trivyFinding.Fingerprint || got[0].Scanner != "trivy" {
		t.Errorf("kept %q/%q, want Trivy's finding", got[0].Scanner, got[0].Fingerprint)
	}
	if want := []string{"osv", "trivy"}; !slices.Equal(got[0].Scanners, want) {
		t.Errorf("scanners = %v, want %v", got[0].Scanners, want)
	}
}
