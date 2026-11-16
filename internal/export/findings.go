package export

import (
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

// Grouped builds one row per rule and type from the latest findings. assetNames
// names the projects; a missing id falls back to "Asset <id>". EPSS columns are
// added only when the feed is enabled, and the row carries the highest score
// among its members.
//
// The folding and ordering belong to reports.GroupFindings, which the grouped
// findings list shares, so the download and the page always agree.
func Grouped(findings []reports.Finding, assetNames map[int64]string, epssEnabled bool) Table {
	groups := reports.GroupFindings(findings)

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

	rows := make([][]Cell, 0, len(groups))
	for _, group := range groups {
		row := []Cell{
			TextCell(group.RuleID),
			TextCell(group.Type),
			TextCell(group.Severity),
			TextCell(group.Title),
			TextCell(strings.Join(group.Packages, ", ")),
			TextCell(strings.Join(groupProjectNames(group.AssetIDs, assetNames), ", ")),
			IntCell(int64(len(group.Findings))),
			IntCell(int64(openCount(group.Findings))),
		}
		if epssEnabled {
			score, percentile, ok := maxEPSS(group.Findings)
			row = append(row, epssCells(ok, score, percentile)...)
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

// openCount is how many members are still open.
func openCount(findings []reports.Finding) int {
	open := 0
	for _, finding := range findings {
		if finding.Status == reports.FindingStatusOpen {
			open++
		}
	}
	return open
}

// maxEPSS is the group's highest member score, the first one when two tie.
func maxEPSS(findings []reports.Finding) (score, percentile float64, ok bool) {
	for _, finding := range findings {
		if finding.EPSS == nil {
			continue
		}
		if !ok || finding.EPSS.Score > score {
			ok = true
			score = finding.EPSS.Score
			percentile = finding.EPSS.Percentile
		}
	}
	return score, percentile, ok
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
