package findings

import (
	"slices"
	"testing"
)

// vuln returns a vulnerability finding with a fingerprint derived from its
// identity, which is what the normalizers produce.
func vuln(ruleID, eco, pkg, version string, sev Severity) Finding {
	f := Finding{
		AssetID:        1,
		Type:           TypeVulnerability,
		RuleID:         ruleID,
		Ecosystem:      eco,
		PackageName:    pkg,
		PackageVersion: version,
		Location:       "package-lock.json",
		Severity:       sev,
	}
	f.Fingerprint = Fingerprint(f.AssetID, f)
	return f
}

func TestMerge(t *testing.T) {
	t.Run("same fingerprint is one finding with occurrences", func(t *testing.T) {
		// DS-0001 reported twice for one Dockerfile (two stages).
		first := Finding{
			AssetID:  1,
			Type:     TypeMisconfig,
			RuleID:   "DS-0001",
			Severity: SeverityMedium,
			Title:    "':latest' tag used",
			Location: "Dockerfile#general",
		}
		first.Fingerprint = Fingerprint(first.AssetID, first)
		second := first

		got := Merge([]Finding{first, second})
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(got), got)
		}
		if got[0].Occurrences != 2 {
			t.Fatalf("occurrences = %d, want 2", got[0].Occurrences)
		}
		if got[0].Title != "':latest' tag used" {
			t.Fatalf("kept finding does not come from the first occurrence: %+v", got[0])
		}
	})

	t.Run("highest severity wins", func(t *testing.T) {
		low := vuln("CVE-2021-1", "npm", "x", "1.0.0", SeverityLow)
		high := vuln("CVE-2021-1", "npm", "x", "2.0.0", SeverityHigh)

		got := Merge([]Finding{low, high})
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1", len(got))
		}
		if got[0].Severity != SeverityHigh {
			t.Fatalf("severity = %q, want high", got[0].Severity)
		}
		if got[0].Occurrences != 2 {
			t.Fatalf("occurrences = %d, want 2", got[0].Occurrences)
		}

		// Input order must not matter for the severity outcome.
		got = Merge([]Finding{high, low})
		if len(got) != 1 || got[0].Severity != SeverityHigh {
			t.Fatalf("reversed order: %+v", got)
		}
	})

	t.Run("distinct fingerprints untouched, singletons count one", func(t *testing.T) {
		a := vuln("CVE-2021-1", "npm", "x", "1.0.0", SeverityHigh)
		b := vuln("CVE-2021-2", "npm", "x", "1.0.0", SeverityLow)

		got := Merge([]Finding{a, b})
		if len(got) != 2 {
			t.Fatalf("got %d findings, want 2", len(got))
		}
		for _, f := range got {
			if f.Occurrences != 1 {
				t.Fatalf("%s occurrences = %d, want 1", f.RuleID, f.Occurrences)
			}
		}
		if got[0].Fingerprint != a.Fingerprint || got[1].Fingerprint != b.Fingerprint {
			t.Fatal("Merge did not preserve input order")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := Merge(nil); len(got) != 0 {
			t.Fatalf("Merge(nil) = %+v, want empty", got)
		}
	})

	t.Run("missing fingerprint is never collapsed", func(t *testing.T) {
		a := Finding{Type: TypeSecret, RuleID: "r", Severity: SeverityHigh}
		b := a
		if got := Merge([]Finding{a, b}); len(got) != 2 {
			t.Fatalf("got %d findings, want 2", len(got))
		}
	})
}

// aliasFinding returns a vulnerability finding from one scanner with an
// advisory alias set, in the place (package, location) the scan reported.
func aliasFinding(scanner, ruleID, pkg, location string, aliases ...string) Finding {
	f := Finding{
		AssetID:        1,
		Type:           TypeVulnerability,
		RuleID:         ruleID,
		Severity:       SeverityHigh,
		Title:          ruleID + " from " + scanner,
		PackageName:    pkg,
		PackageVersion: "4.17.20",
		Ecosystem:      "npm",
		Location:       location,
		Scanner:        scanner,
		Aliases:        aliases,
	}
	f.Fingerprint = Fingerprint(f.AssetID, f)
	return f
}

func TestMergeByAliases(t *testing.T) {
	overlap := func() (trivy, osv Finding) {
		// Trivy reports the CVE and lists the GHSA as a vendor id; OSV reports
		// the GHSA and lists the CVE as an alias.
		return aliasFinding("trivy", "CVE-2021-23337", "lodash", "package-lock.json", "GHSA-35JH-R3H4-6JHM"),
			aliasFinding("osv", "GHSA-35JH-R3H4-6JHM", "lodash", "package-lock.json", "CVE-2021-23337")
	}

	t.Run("GHSA CVE overlap merges with Trivy primary", func(t *testing.T) {
		trivy, osv := overlap()
		trivy.Severity = SeverityMedium
		trivy.Occurrences = 2
		osv.Severity = SeverityHigh

		for _, in := range [][]Finding{{trivy, osv}, {osv, trivy}} {
			got := Merge(in)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(got), got)
			}
			f := got[0]
			if f.Fingerprint != trivy.Fingerprint || f.Scanner != "trivy" {
				t.Errorf("kept %q/%q, want Trivy's %q", f.Scanner, f.Fingerprint, trivy.Fingerprint)
			}
			if f.Title != trivy.Title {
				t.Errorf("title = %q, want Trivy's %q", f.Title, trivy.Title)
			}
			if want := []string{"osv", "trivy"}; !slices.Equal(f.Scanners, want) {
				t.Errorf("scanners = %v, want %v", f.Scanners, want)
			}
			if f.Severity != SeverityHigh {
				t.Errorf("severity = %q, want high", f.Severity)
			}
			// A scanner seeing the same issue does not double its occurrence
			// count; the higher count from within one scanner wins.
			if f.Occurrences != 2 {
				t.Errorf("occurrences = %d, want 2", f.Occurrences)
			}
		}
	})

	tests := []struct {
		name string
		in   []Finding
	}{
		{
			name: "disjoint aliases stay separate",
			in: []Finding{
				aliasFinding("trivy", "CVE-2021-1", "lodash", "package-lock.json", "GHSA-aaaa-bbbb-cccc"),
				aliasFinding("osv", "GHSA-dddd-eeee-ffff", "lodash", "package-lock.json", "CVE-2021-2"),
			},
		},
		{
			name: "same CVE in different packages stays separate",
			in: []Finding{
				aliasFinding("trivy", "CVE-2021-23337", "lodash", "package-lock.json", "GHSA-35JH-R3H4-6JHM"),
				aliasFinding("osv", "GHSA-35JH-R3H4-6JHM", "lodash-es", "package-lock.json", "CVE-2021-23337"),
			},
		},
		{
			name: "same CVE in different locations stays separate",
			in: []Finding{
				aliasFinding("trivy", "CVE-2021-23337", "lodash", "a/package-lock.json", "GHSA-35JH-R3H4-6JHM"),
				aliasFinding("osv", "GHSA-35JH-R3H4-6JHM", "lodash", "b/package-lock.json", "CVE-2021-23337"),
			},
		},
		{
			name: "overlap within one scanner stays separate",
			in: []Finding{
				aliasFinding("trivy", "CVE-2021-23337", "lodash", "package-lock.json", "GHSA-35JH-R3H4-6JHM"),
				aliasFinding("trivy", "GHSA-35JH-R3H4-6JHM", "lodash", "package-lock.json", "CVE-2021-23337"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.in)
			if len(got) != 2 {
				t.Fatalf("got %d findings, want 2: %+v", len(got), got)
			}
			for _, f := range got {
				if len(f.Scanners) != 1 || f.Scanners[0] != f.Scanner {
					t.Errorf("%s scanners = %v, want its own scanner", f.RuleID, f.Scanners)
				}
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	order := []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i]) <= SeverityRank(order[i-1]) {
			t.Fatalf("SeverityRank(%q) <= SeverityRank(%q)", order[i], order[i-1])
		}
	}
	if SeverityRank("bogus") != SeverityRank(SeverityUnknown) {
		t.Fatal("an unknown severity must rank like SeverityUnknown")
	}
}
