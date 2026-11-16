package export

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ozerozdas/bastion/internal/reports"
)

// Views the export endpoint accepts. Grouped folds one row per rule and type
// across projects, exactly like the Findings page; single writes one row per
// finding.
const (
	ViewGrouped = "grouped"
	ViewSingle  = "single"
)

// ValidView reports whether view is one the endpoint can write.
func ValidView(view string) bool {
	return view == ViewGrouped || view == ViewSingle
}

// severityRank orders severities worst first, matching the findings list and
// the UI's grouping.
var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"unknown":  4,
}

// findingGroup is one grouped row under construction: the members and the
// values the row shows.
type findingGroup struct {
	key        string
	ruleID     string
	title      string
	kind       string
	severity   string
	findings   int
	open       int
	assetIDs   []int64
	packages   []string
	hasEPSS    bool
	maxScore   float64
	maxPercent float64
}

// Grouped builds one row per rule and type from the latest findings. assetNames
// names the projects; a missing id falls back to "Asset <id>". EPSS columns are
// added only when the feed is enabled, and the row carries the highest score
// among its members.
//
// The grouping key and the ordering mirror web/src/lib/group-findings.ts: a
// finding without a rule id groups by fingerprint, and rows sort by worst
// severity, then finding count, then title.
func Grouped(findings []reports.Finding, assetNames map[int64]string, epssEnabled bool) Table {
	groups := make(map[string]*findingGroup)
	order := make([]*findingGroup, 0, len(findings))

	for _, finding := range findings {
		ruleID := strings.TrimSpace(finding.RuleID)
		key := ruleID
		if key == "" {
			key = finding.Fingerprint
		}
		key += "\x00" + finding.Type

		group, ok := groups[key]
		if !ok {
			group = &findingGroup{
				key:      key,
				ruleID:   ruleID,
				title:    finding.Title,
				kind:     finding.Type,
				severity: finding.Severity,
			}
			groups[key] = group
			order = append(order, group)
		}

		group.findings++
		if finding.Status == reports.FindingStatusOpen {
			group.open++
		}
		if !containsInt64(group.assetIDs, finding.AssetID) {
			group.assetIDs = append(group.assetIDs, finding.AssetID)
		}
		if name := strings.TrimSpace(finding.PackageName); name != "" && !containsString(group.packages, name) {
			group.packages = append(group.packages, name)
		}
		if rank(finding.Severity) < rank(group.severity) {
			group.severity = finding.Severity
		}
		if finding.EPSS != nil && (!group.hasEPSS || finding.EPSS.Score > group.maxScore) {
			group.hasEPSS = true
			group.maxScore = finding.EPSS.Score
			group.maxPercent = finding.EPSS.Percentile
		}
	}

	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if rank(a.severity) != rank(b.severity) {
			return rank(a.severity) < rank(b.severity)
		}
		if a.findings != b.findings {
			return a.findings > b.findings
		}
		return a.title < b.title
	})

	columns := []Column{
		{Key: "rule", Header: "Rule"},
		{Key: "type", Header: "Type"},
		{Key: "severity", Header: "Severity"},
		{Key: "title", Header: "Title"},
		{Key: "packages", Header: "Packages"},
		{Key: "projects", Header: "Projects"},
		{Key: "findings", Header: "Findings"},
		{Key: "open", Header: "Open"},
	}
	if epssEnabled {
		columns = append(columns,
			Column{Key: "max_epss_score", Header: "Max EPSS"},
			Column{Key: "max_epss_percentile", Header: "Max EPSS percentile"},
		)
	}

	rows := make([][]Cell, 0, len(order))
	for _, group := range order {
		row := []Cell{
			TextCell(group.ruleID),
			TextCell(group.kind),
			TextCell(group.severity),
			TextCell(group.title),
			TextCell(strings.Join(group.packages, ", ")),
			TextCell(strings.Join(groupProjectNames(group.assetIDs, assetNames), ", ")),
			IntCell(int64(group.findings)),
			IntCell(int64(group.open)),
		}
		if epssEnabled {
			row = append(row, epssCells(group.hasEPSS, group.maxScore, group.maxPercent)...)
		}
		rows = append(rows, row)
	}

	return Table{Columns: columns, Rows: rows}
}

// Single builds one row per finding, in the order the findings list returned
// them. assetNames names the projects; a missing id falls back to
// "Asset <id>". EPSS columns are added only when the feed is enabled.
func Single(findings []reports.Finding, assetNames map[int64]string, epssEnabled bool) Table {
	columns := []Column{
		{Key: "project", Header: "Project"},
		{Key: "severity", Header: "Severity"},
		{Key: "type", Header: "Type"},
		{Key: "rule", Header: "Rule"},
		{Key: "title", Header: "Title"},
		{Key: "package", Header: "Package"},
		{Key: "installed_version", Header: "Installed"},
		{Key: "fixed_version", Header: "Fixed"},
		{Key: "location", Header: "Location"},
		{Key: "status", Header: "Status"},
		{Key: "decision", Header: "Decision"},
		{Key: "reason", Header: "Reason"},
		{Key: "expires_at", Header: "Expires at"},
	}
	if epssEnabled {
		columns = append(columns,
			Column{Key: "epss_score", Header: "EPSS"},
			Column{Key: "epss_percentile", Header: "EPSS percentile"},
		)
	}
	columns = append(columns, Column{Key: "first_seen_scan", Header: "First seen (scan)"})

	rows := make([][]Cell, 0, len(findings))
	for _, finding := range findings {
		row := []Cell{
			TextCell(projectName(finding.AssetID, assetNames)),
			TextCell(finding.Severity),
			TextCell(finding.Type),
			TextCell(finding.RuleID),
			TextCell(finding.Title),
			TextCell(finding.PackageName),
			TextCell(finding.PackageVersion),
			TextCell(finding.FixedVersion),
			TextCell(finding.Location),
			TextCell(finding.Status),
			TextCell(finding.State),
			TextCell(finding.Reason),
			TextCell(finding.ExpiresAt),
		}
		if epssEnabled {
			if finding.EPSS != nil {
				row = append(row, NumberCell(finding.EPSS.Score), NumberCell(finding.EPSS.Percentile))
			} else {
				row = append(row, TextCell(""), TextCell(""))
			}
		}
		if finding.FirstSeenScanID != nil {
			row = append(row, IntCell(*finding.FirstSeenScanID))
		} else {
			row = append(row, TextCell(""))
		}
		rows = append(rows, row)
	}

	return Table{Columns: columns, Rows: rows}
}

// epssCells is a grouped row's max EPSS pair, empty when no member has a score.
func epssCells(present bool, score, percentile float64) []Cell {
	if !present {
		return []Cell{TextCell(""), TextCell("")}
	}
	return []Cell{NumberCell(score), NumberCell(percentile)}
}

// groupProjectNames maps the group's asset ids to display names in first-seen
// order.
func groupProjectNames(assetIDs []int64, assetNames map[int64]string) []string {
	names := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		names = append(names, projectName(id, assetNames))
	}
	return names
}

// projectName is an asset's display name, or a stable placeholder.
func projectName(assetID int64, assetNames map[int64]string) string {
	if name, ok := assetNames[assetID]; ok && name != "" {
		return name
	}
	return "Asset " + strconv.FormatInt(assetID, 10)
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
