package findings

// Diff is the change in findings between two scans of the same asset.
type Diff struct {
	// New are fingerprints only in the current scan.
	New []Finding
	// Fixed are fingerprints only in the previous scan.
	Fixed []Finding
	// Persisting are fingerprints in both scans.
	Persisting []Finding
}

// Compare diffs previous against current by fingerprint. Order follows the
// input slices: New and Persisting follow current, Fixed follows previous.
func Compare(previous, current []Finding) Diff {
	prev := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		prev[f.Fingerprint] = struct{}{}
	}
	cur := make(map[string]struct{}, len(current))
	for _, f := range current {
		cur[f.Fingerprint] = struct{}{}
	}

	var d Diff
	for _, f := range current {
		if _, ok := prev[f.Fingerprint]; ok {
			d.Persisting = append(d.Persisting, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for _, f := range previous {
		if _, ok := cur[f.Fingerprint]; !ok {
			d.Fixed = append(d.Fixed, f)
		}
	}
	return d
}
