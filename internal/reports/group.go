package reports

import (
	"sort"
	"strings"
)

// FindingGroup is one rule and type folded across projects (#90). It is the
// single owner of the grouping shared by the grouped findings list and the
// export, so both fold, order and count the same way.
type FindingGroup struct {
	// Key is the rule id (or fingerprint when there is none) plus the type.
	Key           string
	RuleID        string
	Title         string
	Type          string
	Severity      string
	Findings      []Finding
	AssetIDs      []int64
	ProjectCount  int
	Packages      []string
	FixedVersions []string
	// FixedVersion is set only when every member agrees on one.
	FixedVersion string
}

// severityRank orders severities worst first, matching the findings list.
var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"unknown":  4,
}

// GroupFindings folds one row per rule and type from the latest findings,
// keeping the members in the list's order. A finding without a rule id groups
// by fingerprint, which is per-asset, so it only joins identical fingerprints
// from other assets. Rows sort by worst severity, then finding count, then
// title.
func GroupFindings(findings []Finding) []FindingGroup {
	groups := make(map[string]*FindingGroup)
	order := make([]*FindingGroup, 0, len(findings))

	for _, finding := range findings {
		ruleID := strings.TrimSpace(finding.RuleID)
		key := ruleID
		if key == "" {
			key = finding.Fingerprint
		}
		key += "\x00" + finding.Type

		group, ok := groups[key]
		if !ok {
			group = &FindingGroup{
				Key:           key,
				RuleID:        ruleID,
				Title:         finding.Title,
				Type:          finding.Type,
				Severity:      finding.Severity,
				Findings:      make([]Finding, 0, 1),
				AssetIDs:      make([]int64, 0, 1),
				Packages:      make([]string, 0, 1),
				FixedVersions: make([]string, 0, 1),
			}
			groups[key] = group
			order = append(order, group)
		}

		group.Findings = append(group.Findings, finding)
		if !containsInt64(group.AssetIDs, finding.AssetID) {
			group.AssetIDs = append(group.AssetIDs, finding.AssetID)
		}
		if name := strings.TrimSpace(finding.PackageName); name != "" && !containsString(group.Packages, name) {
			group.Packages = append(group.Packages, name)
		}
		if fixed := finding.FixedVersion; fixed != "" && !containsString(group.FixedVersions, fixed) {
			group.FixedVersions = append(group.FixedVersions, fixed)
		}
		if rank(finding.Severity) < rank(group.Severity) {
			group.Severity = finding.Severity
		}
	}

	out := make([]FindingGroup, 0, len(order))
	for _, group := range order {
		group.ProjectCount = len(group.AssetIDs)
		if len(group.FixedVersions) == 1 {
			group.FixedVersion = group.FixedVersions[0]
		}
		out = append(out, *group)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		if len(a.Findings) != len(b.Findings) {
			return len(a.Findings) > len(b.Findings)
		}
		return a.Title < b.Title
	})

	return out
}

// rank is a severity's order; an unknown value sorts last like the API does.
func rank(severity string) int {
	if value, ok := severityRank[severity]; ok {
		return value
	}
	return severityRank["unknown"]
}

func containsInt64(values []int64, value int64) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
