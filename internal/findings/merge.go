package findings

import (
	"slices"
	"strings"
)

// severities orders the §5 scale from least to most severe.
var severities = []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// primaryScanner is the scanner whose finding survives a cross-scanner merge.
// Its fingerprint is the one already stored, so scan diffs and finding states
// do not churn when another scanner reports the same advisory.
const primaryScanner = "trivy"

// SeverityRank returns the position of s on the §5 severity scale: unknown is
// 0 and critical is the highest value. A value outside the scale ranks as
// unknown.
func SeverityRank(s Severity) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return 0
}

// Merge reduces the findings of one scan to one finding per issue. It runs two
// passes:
//
//  1. findings that share a fingerprint are one finding (PROJECT_SPEC.md §5:
//     one finding per fingerprint per scan): the severity is upgraded to the
//     highest seen and the occurrences are summed;
//  2. vulnerability findings in the same place whose advisory alias sets
//     intersect, from different scanners, are one finding, so a CVE reported
//     by both Trivy and OSV is listed once with both scanners.
//
// Findings must already carry a fingerprint.
func Merge(fs []Finding) []Finding {
	if len(fs) == 0 {
		return fs
	}
	return mergeAliases(mergeFingerprints(fs))
}

// mergeFingerprints collapses findings that share a fingerprint. It keeps the
// first occurrence in input order, upgrades the severity to the highest seen
// and sums the occurrences.
func mergeFingerprints(fs []Finding) []Finding {
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

// aliasGroupKey identifies the place one issue is reported at. The location is
// part of the key because Trivy and OSV both derive it from the same inventory
// entry (Trivy's result target): including it keeps the same package reported
// from two different manifests as two findings instead of merging them.
type aliasGroupKey struct {
	assetID   int64
	ecosystem string
	pkg       string
	location  string
}

// mergeAliases collapses vulnerability findings from different scanners whose
// advisory alias sets intersect. Grouping by key first keeps unrelated findings
// out of the quadratic comparison and prevents two packages with the same CVE
// from merging when they are reported in different manifests.
func mergeAliases(fs []Finding) []Finding {
	// Union-find, so a chain of overlapping alias sets (A-B, B-C) ends up as
	// one finding even when A and C share no alias directly.
	parent := make([]int, len(fs))
	for i := range parent {
		parent[i] = i
	}
	union := func(a, b int) {
		ra, rb := findRoot(parent, a), findRoot(parent, b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	groups := make(map[aliasGroupKey][]int, len(fs))
	for i, f := range fs {
		if f.Type != TypeVulnerability {
			continue
		}
		set := aliasSet(f)
		if len(set) == 0 {
			continue
		}
		key := aliasGroupKey{
			assetID:   f.AssetID,
			ecosystem: f.Ecosystem,
			pkg:       f.PackageName,
			location:  f.Location,
		}
		for _, j := range groups[key] {
			// Only cross-scanner overlaps merge. Reference lists can mention
			// related advisories (Trivy's do), and collapsing two distinct
			// findings from one scanner would hide one of them.
			if fs[i].Scanner != fs[j].Scanner && intersects(set, aliasSet(fs[j])) {
				union(i, j)
			}
		}
		groups[key] = append(groups[key], i)
	}

	out := make([]Finding, 0, len(fs))
	emitted := make([]bool, len(fs))
	for i := range fs {
		if emitted[i] {
			continue
		}
		root := findRoot(parent, i)
		members := make([]int, 0, 2)
		for j := i; j < len(fs); j++ {
			if !emitted[j] && findRoot(parent, j) == root {
				members = append(members, j)
			}
		}
		out = append(out, mergeCluster(fs, members))
		for _, j := range members {
			emitted[j] = true
		}
	}
	return out
}

// findRoot returns the representative of i's set, compressing the path as it
// walks to keep later lookups flat.
func findRoot(parent []int, i int) int {
	for parent[i] != i {
		parent[i] = parent[parent[i]]
		i = parent[i]
	}
	return i
}

// mergeCluster combines findings that describe one advisory. Trivy's finding is
// the primary when present, so its fingerprint, title and remediation details
// stay stable. Occurrences are the highest count rather than the sum: the same
// issue seen by two scanners is still one occurrence, while duplicate raw
// findings already summed inside one scanner keep their count.
func mergeCluster(fs []Finding, members []int) Finding {
	primary := members[0]
	if fs[primary].Scanner != primaryScanner {
		for _, j := range members {
			if fs[j].Scanner == primaryScanner {
				primary = j
				break
			}
		}
	}

	merged := fs[primary]
	scanners := make(map[string]struct{}, len(members))
	aliases := make(map[string]struct{}, len(members))
	for _, j := range members {
		f := fs[j]
		if len(f.Scanners) > 0 {
			for _, s := range f.Scanners {
				if s != "" {
					scanners[s] = struct{}{}
				}
			}
		} else if f.Scanner != "" {
			scanners[f.Scanner] = struct{}{}
		}
		addAliases(aliases, f.Aliases)
		if f.Occurrences > merged.Occurrences {
			merged.Occurrences = f.Occurrences
		}
		if SeverityRank(f.Severity) > SeverityRank(merged.Severity) {
			merged.Severity = f.Severity
		}
	}

	merged.Scanner = fs[primary].Scanner
	merged.Fingerprint = fs[primary].Fingerprint
	merged.Scanners = sortedKeys(scanners)
	merged.Aliases = sortedKeys(aliases)
	return merged
}

// aliasSet returns the identifiers that can match one advisory across
// scanners: the rule id plus any aliases, upper-cased because Trivy and OSV do
// not agree on the casing of every id.
func aliasSet(f Finding) map[string]struct{} {
	set := make(map[string]struct{}, len(f.Aliases)+1)
	addAliases(set, []string{f.RuleID})
	addAliases(set, f.Aliases)
	return set
}

// addAliases adds the non-empty ids to set, upper-cased and trimmed.
func addAliases(set map[string]struct{}, ids []string) {
	for _, id := range ids {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			set[id] = struct{}{}
		}
	}
}

// intersects reports whether a and b share an element.
func intersects(a, b map[string]struct{}) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for id := range a {
		if _, ok := b[id]; ok {
			return true
		}
	}
	return false
}

// sortedKeys returns the map keys in sorted order, nil when empty.
func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
