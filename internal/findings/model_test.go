package findings

import (
	"slices"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Severity
	}{
		{name: "critical", in: "critical", want: SeverityCritical},
		{name: "critical upper", in: "CRITICAL", want: SeverityCritical},
		{name: "critical mixed", in: "Critical", want: SeverityCritical},
		{name: "high", in: "high", want: SeverityHigh},
		{name: "high padded", in: "  HIGH\t", want: SeverityHigh},
		{name: "medium", in: "medium", want: SeverityMedium},
		{name: "medium upper padded", in: "\nMedium ", want: SeverityMedium},
		{name: "low", in: "low", want: SeverityLow},
		{name: "low padded", in: " Low ", want: SeverityLow},
		// The normalized "unknown" level is accepted as input, like the others.
		{name: "unknown", in: "unknown", want: SeverityUnknown},
		{name: "unknown upper", in: " UNKNOWN ", want: SeverityUnknown},
		// Anything else is unknown, never dropped and never upgraded.
		{name: "empty", in: "", want: SeverityUnknown},
		{name: "whitespace only", in: "   ", want: SeverityUnknown},
		{name: "scanner-specific moderate", in: "moderate", want: SeverityUnknown},
		{name: "scanner-specific informational", in: "INFO", want: SeverityUnknown},
		{name: "prefix only", in: "crit", want: SeverityUnknown},
		{name: "trailing suffix", in: "highrisk", want: SeverityUnknown},
		{name: "numeric", in: "9.8", want: SeverityUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseSeverity(tc.in); got != tc.want {
				t.Fatalf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// Every level round-trips through its own canonical spelling.
	for _, want := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown} {
		if got := ParseSeverity(string(want)); got != want {
			t.Fatalf("ParseSeverity(%q) = %q, want itself", string(want), got)
		}
	}
}

// sortFinding builds a finding for the sort tests. Only the fields SortFindings
// compares differ; the title identifies the row in failure messages.
func sortFinding(title string, typ Type, ruleID, pkg, ecosystem, location, fingerprint string) Finding {
	return Finding{
		Title:       title,
		Type:        typ,
		RuleID:      ruleID,
		PackageName: pkg,
		Ecosystem:   ecosystem,
		Location:    location,
		Fingerprint: fingerprint,
	}
}

func findingTitles(list []Finding) []string {
	titles := make([]string, len(list))
	for i, f := range list {
		titles[i] = f.Title
	}
	return titles
}

func TestSortFindingsOrdersByEachKey(t *testing.T) {
	// Input is deliberately unsorted. Reading the expected order top to bottom,
	// each consecutive pair differs in exactly the key named in the comment.
	tests := []struct {
		name string
		list []Finding
		want []string
	}{
		{
			name: "type first",
			list: []Finding{
				sortFinding("vulnerability", TypeVulnerability, "a", "a", "go", "a.go", "a"),
				sortFinding("secret", TypeSecret, "a", "a", "go", "a.go", "a"),
				sortFinding("license", TypeLicense, "a", "a", "go", "a.go", "a"),
			},
			want: []string{"license", "secret", "vulnerability"},
		},
		{
			name: "rule id within type",
			list: []Finding{
				sortFinding("rule-b", TypeSecret, "b", "a", "go", "a.go", "a"),
				sortFinding("rule-a", TypeSecret, "a", "a", "go", "a.go", "a"),
			},
			want: []string{"rule-a", "rule-b"},
		},
		{
			name: "package name within type and rule",
			list: []Finding{
				sortFinding("pkg-b", TypeSecret, "a", "b", "go", "a.go", "a"),
				sortFinding("pkg-a", TypeSecret, "a", "a", "go", "a.go", "a"),
			},
			want: []string{"pkg-a", "pkg-b"},
		},
		{
			name: "ecosystem within type, rule and package",
			list: []Finding{
				sortFinding("ecosystem-npm", TypeSecret, "a", "a", "npm", "a.go", "a"),
				sortFinding("ecosystem-go", TypeSecret, "a", "a", "go", "a.go", "a"),
			},
			want: []string{"ecosystem-go", "ecosystem-npm"},
		},
		{
			name: "location within type, rule, package and ecosystem",
			list: []Finding{
				sortFinding("location-b", TypeSecret, "a", "a", "go", "b.go", "a"),
				sortFinding("location-a", TypeSecret, "a", "a", "go", "a.go", "a"),
			},
			want: []string{"location-a", "location-b"},
		},
		{
			name: "fingerprint last",
			list: []Finding{
				sortFinding("fingerprint-b", TypeSecret, "a", "a", "go", "a.go", "bbbb"),
				sortFinding("fingerprint-a", TypeSecret, "a", "a", "go", "a.go", "aaaa"),
			},
			want: []string{"fingerprint-a", "fingerprint-b"},
		},
		{
			name: "full chain",
			list: []Finding{
				sortFinding("vulnerability", TypeVulnerability, "a", "a", "go", "a.go", "aaaa"),
				sortFinding("location-b", TypeSecret, "a", "a", "go", "b.go", "aaaa"),
				sortFinding("rule-b", TypeSecret, "b", "a", "go", "a.go", "aaaa"),
				sortFinding("pkg-b", TypeSecret, "a", "b", "go", "a.go", "aaaa"),
				sortFinding("ecosystem-npm", TypeSecret, "a", "a", "npm", "a.go", "aaaa"),
				sortFinding("license", TypeLicense, "a", "a", "go", "a.go", "aaaa"),
				sortFinding("location-a", TypeSecret, "a", "a", "go", "a.go", "aaaa"),
			},
			want: []string{
				"license",
				"location-a",
				"location-b",
				"ecosystem-npm",
				"pkg-b",
				"rule-b",
				"vulnerability",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SortFindings(tc.list)
			if got := findingTitles(tc.list); !slices.Equal(got, tc.want) {
				t.Fatalf("SortFindings order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSortFindingsDeterministicForTies(t *testing.T) {
	// These two rows compare equal on every key SortFindings looks at: the
	// order between them is left to the sort, so only determinism is asserted.
	first := sortFinding("tie-first", TypeSecret, "a", "a", "go", "a.go", "aaaa")
	second := sortFinding("tie-second", TypeSecret, "a", "a", "go", "a.go", "aaaa")

	one := []Finding{second, first, sortFinding("zeta", TypeSecret, "z", "", "", "", "")}
	two := slices.Clone(one)

	SortFindings(one)
	SortFindings(two)
	if got, want := findingTitles(one), findingTitles(two); !slices.Equal(got, want) {
		t.Fatalf("two sorts of the same input disagree: %v vs %v", got, want)
	}

	// Sorting an already sorted list leaves it unchanged, ties included.
	sorted := findingTitles(one)
	SortFindings(one)
	if got := findingTitles(one); !slices.Equal(got, sorted) {
		t.Fatalf("re-sorting changed the order: %v, want %v", got, sorted)
	}
}

func TestSortFindingsEmpty(t *testing.T) {
	SortFindings(nil)
	empty := []Finding{}
	SortFindings(empty)
	if len(empty) != 0 {
		t.Fatalf("SortFindings on an empty slice produced %d findings", len(empty))
	}

	single := []Finding{sortFinding("only", TypeSecret, "a", "a", "go", "a.go", "a")}
	SortFindings(single)
	if got := findingTitles(single); !slices.Equal(got, []string{"only"}) {
		t.Fatalf("single-element sort = %v, want [only]", got)
	}
}

// sortPackage builds a package for the sort tests; only compared fields differ.
func sortPackage(ecosystem, name, version, path, purl string) Package {
	return Package{Ecosystem: ecosystem, Name: name, Version: version, Path: path, PURL: purl}
}

func packageKeys(list []Package) []string {
	keys := make([]string, len(list))
	for i, p := range list {
		keys[i] = p.Ecosystem + "|" + p.Name + "|" + p.Version + "|" + p.Path + "|" + p.PURL
	}
	return keys
}

func TestSortPackagesOrdersByEachKey(t *testing.T) {
	tests := []struct {
		name string
		list []Package
		want []string
	}{
		{
			name: "ecosystem",
			list: []Package{
				sortPackage("npm", "a", "1", "p", "u"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{"go|a|1|p|u", "npm|a|1|p|u"},
		},
		{
			name: "name within ecosystem",
			list: []Package{
				sortPackage("go", "b", "1", "p", "u"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{"go|a|1|p|u", "go|b|1|p|u"},
		},
		{
			name: "version within ecosystem and name",
			list: []Package{
				sortPackage("go", "a", "2", "p", "u"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{"go|a|1|p|u", "go|a|2|p|u"},
		},
		{
			name: "path within ecosystem, name and version",
			list: []Package{
				sortPackage("go", "a", "1", "q", "u"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{"go|a|1|p|u", "go|a|1|q|u"},
		},
		{
			name: "purl last",
			list: []Package{
				sortPackage("go", "a", "1", "p", "v"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{"go|a|1|p|u", "go|a|1|p|v"},
		},
		{
			name: "full chain",
			list: []Package{
				sortPackage("npm", "a", "1", "p", "u"),
				sortPackage("go", "b", "1", "p", "u"),
				sortPackage("go", "a", "2", "p", "u"),
				sortPackage("go", "a", "1", "q", "u"),
				sortPackage("go", "a", "1", "p", "v"),
				sortPackage("go", "a", "1", "p", "u"),
			},
			want: []string{
				"go|a|1|p|u",
				"go|a|1|p|v",
				"go|a|1|q|u",
				"go|a|2|p|u",
				"go|b|1|p|u",
				"npm|a|1|p|u",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SortPackages(tc.list)
			if got := packageKeys(tc.list); !slices.Equal(got, tc.want) {
				t.Fatalf("SortPackages order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSortPackagesDeterministicForTies(t *testing.T) {
	// Equal on every compared key: their relative order is the sort's, so
	// assert determinism and idempotency instead of a fixed order.
	first := sortPackage("go", "a", "1", "p", "u")
	first.Direct = boolPtr(true)
	second := sortPackage("go", "a", "1", "p", "u")
	second.Direct = boolPtr(false)

	one := []Package{second, sortPackage("npm", "a", "1", "p", "u"), first}
	two := slices.Clone(one)

	SortPackages(one)
	SortPackages(two)
	if got, want := packageKeys(one), packageKeys(two); !slices.Equal(got, want) {
		t.Fatalf("two sorts of the same input disagree: %v vs %v", got, want)
	}

	sorted := packageKeys(one)
	SortPackages(one)
	if got := packageKeys(one); !slices.Equal(got, sorted) {
		t.Fatalf("re-sorting changed the order: %v, want %v", got, sorted)
	}
}

func TestSortPackagesEmpty(t *testing.T) {
	SortPackages(nil)
	empty := []Package{}
	SortPackages(empty)
	if len(empty) != 0 {
		t.Fatalf("SortPackages on an empty slice produced %d packages", len(empty))
	}
}

func boolPtr(v bool) *bool { return &v }
