package findings

import "slices"

// severities orders the §5 scale from least to most severe.
var severities = []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// SeverityRank returns the position of s on the §5 severity scale: unknown is
// 0 and critical is the highest value. A value outside the scale ranks as
// unknown.
func SeverityRank(s Severity) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return 0
}

// Merge collapses findings that share a fingerprint into one finding
// (PROJECT_SPEC.md §5: one finding per fingerprint per scan). It keeps the
// first occurrence in input order, upgrades the severity to the highest seen
// and counts the occurrences. Findings must already carry a fingerprint.
func Merge(fs []Finding) []Finding {
	if len(fs) == 0 {
		return fs
	}
	out := make([]Finding, 0, len(fs))
	index := make(map[string]int, len(fs))
	for _, f := range fs {
		if f.Occurrences < 1 {
			f.Occurrences = 1
		}
		if f.Fingerprint == "" {
			// Without a fingerprint two findings cannot be compared; keeping
			// them apart is safer than collapsing them into one.
			out = append(out, f)
			continue
		}
		i, seen := index[f.Fingerprint]
		if !seen {
			index[f.Fingerprint] = len(out)
			out = append(out, f)
			continue
		}
		kept := &out[i]
		kept.Occurrences += f.Occurrences
		if SeverityRank(f.Severity) > SeverityRank(kept.Severity) {
			kept.Severity = f.Severity
		}
	}
	return out
}
