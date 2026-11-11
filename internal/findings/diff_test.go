package findings

import "testing"

func TestCompare(t *testing.T) {
	a := Finding{Fingerprint: "a"}
	b := Finding{Fingerprint: "b"}
	c := Finding{Fingerprint: "c"}
	d := Finding{Fingerprint: "d"}

	got := Compare([]Finding{a, b, c}, []Finding{b, d, a})

	if len(got.New) != 1 || got.New[0].Fingerprint != "d" {
		t.Fatalf("New = %+v, want [d]", got.New)
	}
	if len(got.Persisting) != 2 || got.Persisting[0].Fingerprint != "b" || got.Persisting[1].Fingerprint != "a" {
		t.Fatalf("Persisting = %+v, want [b a]", got.Persisting)
	}
	if len(got.Fixed) != 1 || got.Fixed[0].Fingerprint != "c" {
		t.Fatalf("Fixed = %+v, want [c]", got.Fixed)
	}
}

func TestCompareEmpty(t *testing.T) {
	got := Compare(nil, nil)
	if len(got.New) != 0 || len(got.Fixed) != 0 || len(got.Persisting) != 0 {
		t.Fatalf("Compare(nil, nil) = %+v, want empty diff", got)
	}
}
