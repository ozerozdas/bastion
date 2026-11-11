package findings

import "testing"

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
