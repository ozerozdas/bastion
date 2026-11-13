package findings

// Diff is the change in findings between two scans of the same asset.
type Diff = DiffOf[Finding]

// DiffOf is Diff over any finding read model, such as the API's finding shape.
type DiffOf[T any] struct {
	// New are fingerprints only in the current set.
	New []T
	// Fixed are fingerprints only in the previous set.
	Fixed []T
	// Persisting are fingerprints in both sets, taken from the current one.
	Persisting []T
}

// Compare diffs previous against current by fingerprint. Order follows the
// input slices: New and Persisting follow current, Fixed follows previous.
func Compare(previous, current []Finding) Diff {
	return CompareBy(previous, current, func(f Finding) string { return f.Fingerprint })
}

// CompareBy diffs previous against current by fingerprint. It is Compare for a
// read model that is not Finding, such as the API's richer finding shape, so
// both a scan diff and the API response match on the same identity.
func CompareBy[T any](previous, current []T, fingerprint func(T) string) DiffOf[T] {
	prev := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		prev[fingerprint(f)] = struct{}{}
	}
	cur := make(map[string]struct{}, len(current))
	for _, f := range current {
		cur[fingerprint(f)] = struct{}{}
	}

	var d DiffOf[T]
	for _, f := range current {
		if _, ok := prev[fingerprint(f)]; ok {
			d.Persisting = append(d.Persisting, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for _, f := range previous {
		if _, ok := cur[fingerprint(f)]; !ok {
			d.Fixed = append(d.Fixed, f)
		}
	}
	return d
}
