package fixplan

import (
	"reflect"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

// TestBuildGroupsByPackageAndMinimalFix is the Done-when fixture: several CVEs
// in one package become one step with the highest minimal fixed version and the
// right counts.
func TestBuildGroupsByPackageAndMinimalFix(t *testing.T) {
	plan := Build([]Input{
		{ID: 1, Ecosystem: "npm", PackageName: "lodash", PackageVersion: "4.17.0", FixedVersion: "4.17.19", Severity: findings.SeverityCritical},
		{ID: 2, Ecosystem: "npm", PackageName: "lodash", PackageVersion: "4.17.0", FixedVersion: "4.17.21", Severity: findings.SeverityHigh},
		// A comma list: the smallest candidate above the installed version wins.
		{ID: 3, Ecosystem: "npm", PackageName: "lodash", PackageVersion: "4.17.0", FixedVersion: "4.17.11, 4.17.21", Severity: findings.SeverityMedium},
	})

	if len(plan.Steps) != 1 || len(plan.NoFix) != 0 {
		t.Fatalf("plan = %+v, want one step and no no_fix", plan)
	}
	step := plan.Steps[0]
	want := Step{
		Ecosystem:         "npm",
		Package:           "lodash",
		InstalledVersions: []string{"4.17.0"},
		TargetVersion:     "4.17.21",
		FindingCount:      3,
		SeverityCounts:    SeverityCounts{Critical: 1, High: 1, Medium: 1},
		FindingIDs:        []int64{1, 2, 3},
	}
	if !reflect.DeepEqual(step, want) {
		t.Errorf("step = %+v, want %+v", step, want)
	}
}

// TestBuildListsFindingsWithoutFixSeparately proves findings no upgrade closes
// leave the steps and land in no_fix, grouped by package.
func TestBuildListsFindingsWithoutFixSeparately(t *testing.T) {
	plan := Build([]Input{
		{ID: 10, Ecosystem: "os-deb", PackageName: "openssl", PackageVersion: "1.1.1n", Severity: findings.SeverityHigh},
		{ID: 11, Ecosystem: "os-deb", PackageName: "openssl", PackageVersion: "1.1.1n", Severity: findings.SeverityLow},
		// A fixed version that is not above the installed one cannot be the target.
		{ID: 12, Ecosystem: "npm", PackageName: "minimist", PackageVersion: "1.2.5", FixedVersion: "1.2.5", Severity: findings.SeverityMedium},
		{ID: 13, Ecosystem: "npm", PackageName: "left-pad", PackageVersion: "1.3.0", FixedVersion: "1.3.1", Severity: findings.SeverityCritical},
	})

	if len(plan.Steps) != 1 || plan.Steps[0].Package != "left-pad" {
		t.Fatalf("steps = %+v, want only left-pad", plan.Steps)
	}
	want := []NoFix{
		{Ecosystem: "os-deb", Package: "openssl", FindingCount: 2, SeverityCounts: SeverityCounts{High: 1, Low: 1}, FindingIDs: []int64{10, 11}},
		{Ecosystem: "npm", Package: "minimist", FindingCount: 1, SeverityCounts: SeverityCounts{Medium: 1}, FindingIDs: []int64{12}},
	}
	if !reflect.DeepEqual(plan.NoFix, want) {
		t.Errorf("no_fix = %+v, want %+v", plan.NoFix, want)
	}
}

// TestBuildGroupsPerEcosystem keeps same-named packages apart and orders steps
// by critical findings, then high, then total count.
func TestBuildGroupsPerEcosystem(t *testing.T) {
	plan := Build([]Input{
		{ID: 1, Ecosystem: "npm", PackageName: "tar", PackageVersion: "6.0.0", FixedVersion: "6.1.0", Severity: findings.SeverityHigh},
		{ID: 2, Ecosystem: "go", PackageName: "tar", PackageVersion: "v1.0.0", FixedVersion: "v1.0.1", Severity: findings.SeverityCritical},
		{ID: 3, Ecosystem: "npm", PackageName: "tar", PackageVersion: "6.0.0", FixedVersion: "6.1.1", Severity: findings.SeverityHigh},
	})

	if len(plan.Steps) != 2 {
		t.Fatalf("steps = %+v, want one per ecosystem", plan.Steps)
	}
	if plan.Steps[0].Ecosystem != "go" {
		t.Errorf("first step = %+v, want the critical Go step", plan.Steps[0])
	}
	if plan.Steps[0].TargetVersion != "v1.0.1" {
		t.Errorf("go target = %q, want v1.0.1", plan.Steps[0].TargetVersion)
	}
	if plan.Steps[1].TargetVersion != "6.1.1" {
		t.Errorf("npm target = %q, want 6.1.1", plan.Steps[1].TargetVersion)
	}
	if plan.Steps[1].FindingCount != 2 {
		t.Errorf("npm step = %+v, want two findings", plan.Steps[1])
	}
}

// TestBuildUsesEcosystemVersionOrder covers the OS and Python parsers through
// the plan: a Debian revision list, an apk revision and a PEP 440 pre-release.
func TestBuildUsesEcosystemVersionOrder(t *testing.T) {
	cases := []struct {
		name        string
		input       Input
		want        string
		approximate bool
	}{
		{
			name:  "debian revision list",
			input: Input{ID: 1, Ecosystem: "os-deb", PackageName: "curl", PackageVersion: "7.74.0", FixedVersion: "7.74.0-1.3+deb11u7, 7.88.1-10+deb12u5", Severity: findings.SeverityHigh},
			want:  "7.74.0-1.3+deb11u7",
		},
		{
			name:  "apk revision",
			input: Input{ID: 2, Ecosystem: "os-apk", PackageName: "busybox", PackageVersion: "1.34.1-r3", FixedVersion: "1.34.1-r5", Severity: findings.SeverityHigh},
			want:  "1.34.1-r5",
		},
		{
			name:  "pep 440",
			input: Input{ID: 3, Ecosystem: "pypi", PackageName: "django", PackageVersion: "3.2", FixedVersion: "3.2.1, 4.0", Severity: findings.SeverityHigh},
			want:  "3.2.1",
		},
		{
			name:  "rpm release",
			input: Input{ID: 4, Ecosystem: "os-rpm", PackageName: "glibc", PackageVersion: "2.28-151.el8", FixedVersion: "2.28-164.el8", Severity: findings.SeverityHigh},
			want:  "2.28-164.el8",
		},
		{
			name:  "npm range lower bound",
			input: Input{ID: 6, Ecosystem: "npm", PackageName: "lodash", PackageVersion: "3.10.1", FixedVersion: ">=4.17.11", Severity: findings.SeverityHigh},
			want:  "4.17.11",
		},
		{
			name:        "unknown ecosystem falls back",
			input:       Input{ID: 5, Ecosystem: "hex", PackageName: "plug", PackageVersion: "1.10.0", FixedVersion: "1.11.0", Severity: findings.SeverityHigh},
			want:        "1.11.0",
			approximate: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := Build([]Input{tc.input})
			if len(plan.Steps) != 1 {
				t.Fatalf("steps = %+v, want one", plan.Steps)
			}
			if got := plan.Steps[0].TargetVersion; got != tc.want {
				t.Errorf("target = %q, want %q", got, tc.want)
			}
			if got := plan.Steps[0].Approximate; got != tc.approximate {
				t.Errorf("approximate = %v, want %v", got, tc.approximate)
			}
		})
	}
}

// TestCompareVersions pins the comparison each supported ecosystem uses, and
// the fallbacks: an unknown ecosystem or unreadable values are never exact.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		a, b      string
		want      int
		exact     bool
	}{
		{name: "npm", ecosystem: "npm", a: "1.2.3", b: "1.10.0", want: -1, exact: true},
		{name: "npm prerelease", ecosystem: "npm", a: "1.2.3-beta", b: "1.2.3", want: -1, exact: true},
		{name: "go module", ecosystem: "go", a: "v1.2.3", b: "v1.10.0", want: -1, exact: true},
		{name: "go pseudo-version", ecosystem: "go", a: "v0.0.0-20240101000000-abcdefabcdef", b: "v0.1.0", want: -1, exact: true},
		{name: "go without v falls back", ecosystem: "go", a: "1.2.3", b: "1.10.0", want: -1, exact: false},
		{name: "debian", ecosystem: "os-deb", a: "1.0-1", b: "1.0-2", want: -1, exact: true},
		{name: "debian epoch", ecosystem: "os-deb", a: "1:1.0", b: "2.0", want: 1, exact: true},
		{name: "apk", ecosystem: "os-apk", a: "1.2.3-r1", b: "1.2.3-r2", want: -1, exact: true},
		{name: "rpm", ecosystem: "os-rpm", a: "1.0-1", b: "1.0-2", want: -1, exact: true},
		{name: "pep 440", ecosystem: "pypi", a: "1.0.0", b: "1.0.1", want: -1, exact: true},
		{name: "pep 440 pre-release", ecosystem: "pypi", a: "1.0rc1", b: "1.0", want: -1, exact: true},
		{name: "unknown ecosystem", ecosystem: "maven", a: "1.0", b: "1.1", want: -1, exact: false},
		{name: "unreadable values", ecosystem: "npm", a: "alpha", b: "beta", want: -1, exact: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, exact := compareVersions(tc.ecosystem, tc.a, tc.b)
			if got != tc.want || exact != tc.exact {
				t.Errorf("compareVersions(%q, %q, %q) = %d, %v; want %d, %v",
					tc.ecosystem, tc.a, tc.b, got, exact, tc.want, tc.exact)
			}
		})
	}
}

// TestBuildEmpty keeps both lists non-nil, so the API always serializes arrays.
func TestBuildEmpty(t *testing.T) {
	plan := Build(nil)
	if plan.Steps == nil || plan.NoFix == nil {
		t.Fatalf("plan = %+v, want empty non-nil lists", plan)
	}
}
