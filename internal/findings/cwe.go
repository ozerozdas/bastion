package findings

import (
	"regexp"
	"slices"
	"strconv"
)

// cweID matches a CWE id inside a scanner's label. Opengrep rules carry the
// weakness title after the id ("CWE-89: Improper Neutralization..."), and some
// sources put several ids in one string.
var cweID = regexp.MustCompile(`(?i)CWE-([0-9]+)`)

// NormalizeCWEIDs turns the CWE labels a scanner reported into canonical
// "CWE-<n>" ids, drops duplicates and sorts them by number. Labels that carry
// no id are ignored, so an empty or unrecognised list yields nil.
func NormalizeCWEIDs(labels []string) []string {
	seen := make(map[int]struct{}, len(labels))
	for _, label := range labels {
		for _, match := range cweID.FindAllStringSubmatch(label, -1) {
			n, err := strconv.Atoi(match[1])
			if err != nil || n <= 0 {
				continue
			}
			seen[n] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	numbers := make([]int, 0, len(seen))
	for n := range seen {
		numbers = append(numbers, n)
	}
	slices.Sort(numbers)
	ids := make([]string, len(numbers))
	for i, n := range numbers {
		ids[i] = "CWE-" + strconv.Itoa(n)
	}
	return ids
}
