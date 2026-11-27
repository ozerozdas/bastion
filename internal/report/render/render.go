// Package render turns a reports.Snapshot into an offline document: JSON for
// machines, GitHub-flavoured Markdown for pull requests and a self-contained
// HTML page for reading or printing (#204). Every renderer is deterministic:
// it reads only the snapshot, iterates slices (never maps) and never calls the
// clock, so the same snapshot renders to the same bytes.
package render

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/reports"
)

const (
	// timestampLayout is the human timestamp format the Markdown and HTML
	// documents use; JSON keeps the struct's RFC 3339 timestamps.
	timestampLayout = "2006-01-02 15:04 UTC"
	// noneLine marks a section, or a table inside one, with no data.
	noneLine = "None."
	// failedScannerStatus is the scanner_runs status a failed run carries.
	failedScannerStatus = "failed"
	// dash stands in for an absent value.
	dash = "—"
)

//go:embed template.html
var templateSource string

// reportTemplate is parsed once; the template is static, so a parse failure is
// a programming error and panics at init.
var reportTemplate = template.Must(template.New("snapshot.html").Funcs(template.FuncMap{
	"timestamp":        timestamp,
	"timestampPtr":     timestampPtr,
	"scope":            scopeLine,
	"asset":            assetLabel,
	"ruleAsset":        ruleAsset,
	"failedScanners":   failedScanners,
	"lastScanStatus":   lastScanStatus,
	"lastScanFinished": lastScanFinished,
	"finding":          findingLabel,
	"meanTimeToFix":    meanTimeToFix,
	"counts":           decisionCountsLine,
	"list":             listOrDash,
	"dash":             textOrDash,
	"yesNo":            yesNo,
}).Parse(templateSource))

// JSON writes the snapshot as indented JSON with a trailing newline. The
// struct's slices and field order, never maps, keep the encoding stable.
func JSON(w io.Writer, s reports.Snapshot) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(s); err != nil {
		return fmt.Errorf("render snapshot as json: %w", err)
	}
	return nil
}

// Markdown writes the snapshot as GitHub-flavoured Markdown. Sections follow
// the snapshot's field order, and every table cell is escaped, so a finding
// title or decision reason can carry a pipe, a backtick or a newline.
func Markdown(w io.Writer, s reports.Snapshot) error {
	var out strings.Builder
	writeMarkdown(&out, s)
	if _, err := io.WriteString(w, out.String()); err != nil {
		return fmt.Errorf("render snapshot as markdown: %w", err)
	}
	return nil
}

// HTML writes the snapshot as one self-contained HTML document. html/template
// escapes every value, so a finding title or reason cannot inject markup; the
// page carries inline CSS only, with no script and no external asset.
func HTML(w io.Writer, s reports.Snapshot) error {
	if err := reportTemplate.Execute(w, s); err != nil {
		return fmt.Errorf("render snapshot as html: %w", err)
	}
	return nil
}

// writeMarkdown writes the whole document, so a failed writer never leaves a
// half-built table behind.
func writeMarkdown(out *strings.Builder, s reports.Snapshot) {
	out.WriteString("# Bastion security report\n\n")
	fmt.Fprintf(out, "Generated %s · Scope: %s\n\n", timestamp(s.GeneratedAt), inlineText(scopeLine(s.Scope)))

	writeCoverage(out, s.Coverage)
	writeFindings(out, s.Findings)
	writeSLA(out, s.SLA)
	writeDecisions(out, s.Decisions)
	writeRules(out, s.SuppressionRules)
	writeLicence(out, s.LicencePolicy)
}

// writeCoverage writes the asset coverage summary and table.
func writeCoverage(out *strings.Builder, coverage reports.SnapshotCoverage) {
	out.WriteString("## Coverage\n\n")
	if coverage.AssetsTotal == 0 && len(coverage.Assets) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	fmt.Fprintf(out, "%d assets: %d scanned, %d never scanned, %d last scan failed.\n\n",
		coverage.AssetsTotal, coverage.Scanned, coverage.NeverScanned, coverage.LastScanFailed)

	rows := make([][]string, 0, len(coverage.Assets))
	for _, asset := range coverage.Assets {
		rows = append(rows, []string{
			assetLabel(asset.DisplayName, asset.AssetID),
			asset.Kind,
			lastScanStatus(asset.LastScan),
			lastScanFinished(asset.LastScan),
			failedScanners(asset.Scanners),
		})
	}
	writeTable(out, []string{"Asset", "Kind", "Last scan status", "Finished", "Failed scanners"}, rows)
}

// writeFindings writes the fleet totals and the per-asset open finding counts.
func writeFindings(out *strings.Builder, findings reports.SnapshotFindings) {
	out.WriteString("## Open findings\n\n")
	if len(findings.Assets) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	totals := findings.Total
	fmt.Fprintf(out, "%d open: %d critical, %d high, %d medium, %d low, %d unknown.\n\n",
		findings.Open, totals.Critical, totals.High, totals.Medium, totals.Low, totals.Unknown)

	rows := make([][]string, 0, len(findings.Assets))
	for _, asset := range findings.Assets {
		rows = append(rows, []string{
			assetLabel(asset.DisplayName, asset.AssetID),
			asset.Kind,
			strconv.Itoa(asset.Total),
			strconv.Itoa(asset.Severity.Critical),
			strconv.Itoa(asset.Severity.High),
			strconv.Itoa(asset.Severity.Medium),
			strconv.Itoa(asset.Severity.Low),
			strconv.Itoa(asset.Severity.Unknown),
		})
	}
	writeTable(out, []string{"Asset", "Kind", "Total", "Critical", "High", "Medium", "Low", "Unknown"}, rows)
}

// writeSLA writes the thresholds, the counts and the overdue findings.
func writeSLA(out *strings.Builder, sla reports.SnapshotSLA) {
	out.WriteString("## SLA\n\n")
	if sla.OpenCount == 0 && sla.OverdueCount == 0 && len(sla.Overdue) == 0 &&
		sla.FixedInWindow == 0 && sla.MeanTimeToFixDays == nil {
		out.WriteString(noneLine + "\n\n")
		return
	}
	fmt.Fprintf(out, "Thresholds: %d days critical, %d days high, %d days medium, %d days low. Fix window: %d days.\n\n",
		sla.Thresholds.Critical, sla.Thresholds.High, sla.Thresholds.Medium, sla.Thresholds.Low, sla.WindowDays)
	fmt.Fprintf(out, "%d open, %d overdue", sla.OpenCount, sla.OverdueCount)
	if sla.OverdueTruncated {
		out.WriteString(" (list truncated)")
	}
	fmt.Fprintf(out, ", %d fixed in the window, mean time to fix %s.\n\n",
		sla.FixedInWindow, meanTimeToFix(sla.MeanTimeToFixDays))

	if len(sla.Overdue) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	rows := make([][]string, 0, len(sla.Overdue))
	for _, overdue := range sla.Overdue {
		rows = append(rows, []string{
			assetLabel(overdue.AssetName, overdue.AssetID),
			findingLabel(overdue.Title, overdue.RuleID, overdue.Fingerprint),
			overdue.Severity,
			timestamp(overdue.FirstSeen),
			strconv.Itoa(overdue.AgeDays),
			strconv.Itoa(overdue.ThresholdDays),
			strconv.Itoa(overdue.OverdueDays),
		})
	}
	writeTable(out, []string{
		"Asset", "Finding", "Severity", "First seen", "Age days", "Threshold days", "Overdue days",
	}, rows)
}

// writeDecisions writes the decision tallies and every stored decision.
func writeDecisions(out *strings.Builder, decisions reports.SnapshotDecisions) {
	out.WriteString("## Triage decisions\n\n")
	if decisions.Total == 0 && len(decisions.Entries) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	fmt.Fprintf(out, "%d decisions, %d expired.\n\n", decisions.Total, decisions.Expired)
	fmt.Fprintf(out, "By state: %s.\n\n", inlineText(decisionCountsLine(decisions.ByState)))
	fmt.Fprintf(out, "By decided by: %s.\n\n", inlineText(decisionCountsLine(decisions.ByDecidedBy)))

	if len(decisions.Entries) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	rows := make([][]string, 0, len(decisions.Entries))
	for _, decision := range decisions.Entries {
		rows = append(rows, []string{
			assetLabel(decision.AssetName, decision.AssetID),
			findingLabel(decision.Title, decision.RuleID, decision.Fingerprint),
			decision.Severity,
			decision.State,
			textOrDash(decision.Reason),
			textOrDash(decision.DecidedBy),
			timestampPtr(decision.ExpiresAt),
			yesNo(decision.Expired),
		})
	}
	writeTable(out, []string{
		"Asset", "Finding", "Severity", "State", "Reason", "Decided by", "Expires", "Expired",
	}, rows)
}

// writeRules writes the suppression rule tallies and the active rules.
func writeRules(out *strings.Builder, rules reports.SnapshotSuppressionRules) {
	out.WriteString("## Suppression rules\n\n")
	if rules.ActiveCount == 0 && rules.ProposedCount == 0 && len(rules.Rules) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	fmt.Fprintf(out, "%d active, %d proposed.\n\n", rules.ActiveCount, rules.ProposedCount)

	if len(rules.Rules) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	rows := make([][]string, 0, len(rules.Rules))
	for _, rule := range rules.Rules {
		rows = append(rows, []string{
			strconv.FormatInt(rule.ID, 10),
			ruleAsset(rule),
			textOrDash(rule.FindingType),
			textOrDash(rule.RuleID),
			textOrDash(rule.PackageName),
			textOrDash(rule.PathGlob),
			textOrDash(rule.State),
			textOrDash(rule.Reason),
			timestampPtr(rule.ExpiresAt),
			yesNo(rule.Expired),
			textOrDash(rule.CreatedBy),
			strconv.Itoa(rule.Matched),
		})
	}
	writeTable(out, []string{
		"ID", "Asset", "Finding type", "Rule ID", "Package", "Path glob",
		"State", "Reason", "Expires", "Expired", "Created by", "Matched",
	}, rows)
}

// writeLicence writes the global licence policy and the per-asset policies.
func writeLicence(out *strings.Builder, policy reports.SnapshotLicencePolicy) {
	out.WriteString("## Licence policy\n\n")
	if len(policy.Global.Allow) == 0 && len(policy.Global.Deny) == 0 && len(policy.Assets) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	fmt.Fprintf(out, "Global allow: %s\n\n", inlineText(listOrDash(policy.Global.Allow)))
	fmt.Fprintf(out, "Global deny: %s\n\n", inlineText(listOrDash(policy.Global.Deny)))

	if len(policy.Assets) == 0 {
		out.WriteString(noneLine + "\n\n")
		return
	}
	rows := make([][]string, 0, len(policy.Assets))
	for _, asset := range policy.Assets {
		rows = append(rows, []string{
			assetLabel(asset.AssetName, asset.AssetID),
			listOrDash(asset.Allow),
			listOrDash(asset.Deny),
		})
	}
	writeTable(out, []string{"Asset", "Allow", "Deny"}, rows)
}

// writeTable writes a GitHub table. Every cell is escaped, so data can never
// split a row or open an inline span.
func writeTable(out *strings.Builder, headers []string, rows [][]string) {
	out.WriteString("| ")
	for i, header := range headers {
		if i > 0 {
			out.WriteString(" | ")
		}
		out.WriteString(markdownCell(header))
	}
	out.WriteString(" |\n|")
	for range headers {
		out.WriteString(" --- |")
	}
	out.WriteString("\n")
	for _, row := range rows {
		out.WriteString("| ")
		for i, value := range row {
			if i > 0 {
				out.WriteString(" | ")
			}
			out.WriteString(markdownCell(value))
		}
		out.WriteString(" |\n")
	}
	out.WriteString("\n")
}

// markdownCell escapes a table cell: a pipe would split it, a backtick would
// open a code span, a newline would end the row and markup would survive.
func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "`", "\\`")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\n", "<br>")
}

// inlineText escapes a data value written into prose: the same entities as a
// table cell, but a newline becomes one space (so it cannot start a block) and
// a leading block marker is escaped. It runs inside the Markdown writer only;
// the HTML template gets the raw value and escapes it itself.
func inlineText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "`", "\\`")
	return escapeBlockStart(value)
}

// escapeBlockStart neutralises a heading, list or quote marker at the start of
// a line, ignoring leading spaces, so an escaped value cannot open a block.
func escapeBlockStart(value string) string {
	lead := value[:len(value)-len(strings.TrimLeft(value, " "))]
	rest := value[len(lead):]
	switch {
	case strings.HasPrefix(rest, "#"), strings.HasPrefix(rest, "-"), strings.HasPrefix(rest, ">"):
		return lead + "\\" + rest
	}
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits > 0 && digits < len(rest) && rest[digits] == '.' {
		return lead + rest[:digits] + "\\" + rest[digits:]
	}
	return value
}

// timestamp formats a time in UTC; the zero time is absent.
func timestamp(value time.Time) string {
	if value.IsZero() {
		return dash
	}
	return value.UTC().Format(timestampLayout)
}

// timestampPtr formats a nullable time; nil and the zero time are absent.
func timestampPtr(value *time.Time) string {
	if value == nil {
		return dash
	}
	return timestamp(*value)
}

// scopeLine names what the snapshot covers.
func scopeLine(scope reports.SnapshotScope) string {
	if scope.AssetID == nil {
		return "whole fleet"
	}
	return "asset " + assetLabel(scope.AssetName, *scope.AssetID)
}

// assetLabel names an asset, falling back to its id.
func assetLabel(name string, id int64) string {
	if name != "" {
		return name
	}
	return "asset #" + strconv.FormatInt(id, 10)
}

// ruleAsset names a rule's scope: every asset for a global rule.
func ruleAsset(rule reports.SnapshotRule) string {
	if rule.AssetID == nil {
		return "all assets"
	}
	return assetLabel(rule.AssetName, *rule.AssetID)
}

// lastScanStatus is the newest scan's status, or that the asset was never
// scanned.
func lastScanStatus(scan *reports.SnapshotLastScan) string {
	if scan == nil {
		return "never scanned"
	}
	return textOrDash(scan.Status)
}

// lastScanFinished is when the newest scan finished, when it did.
func lastScanFinished(scan *reports.SnapshotLastScan) string {
	if scan == nil {
		return dash
	}
	return timestampPtr(scan.FinishedAt)
}

// failedScanners lists the scanner runs that failed, or a dash when none did.
func failedScanners(runs []reports.SnapshotScannerRun) string {
	names := make([]string, 0, len(runs))
	for _, run := range runs {
		if run.Status != failedScannerStatus {
			continue
		}
		if run.Name == "" {
			names = append(names, "unnamed")
			continue
		}
		names = append(names, run.Name)
	}
	if len(names) == 0 {
		return dash
	}
	return strings.Join(names, ", ")
}

// findingLabel names a finding by its title, then its rule id and then its
// fingerprint.
func findingLabel(title, ruleID, fingerprint string) string {
	switch {
	case title != "":
		return title
	case ruleID != "":
		return ruleID
	case fingerprint != "":
		return fingerprint
	default:
		return dash
	}
}

// meanTimeToFix formats the fix average, which is absent for a window with no
// fix.
func meanTimeToFix(mean *float64) string {
	if mean == nil {
		return dash
	}
	return strconv.FormatFloat(*mean, 'f', -1, 64) + " days"
}

// decisionCountsLine renders one tally list as "key count, key count".
func decisionCountsLine(counts []reports.SnapshotDecisionCount) string {
	if len(counts) == 0 {
		return dash
	}
	parts := make([]string, 0, len(counts))
	for _, count := range counts {
		parts = append(parts, count.Key+" "+strconv.Itoa(count.Count))
	}
	return strings.Join(parts, ", ")
}

// listOrDash joins a policy list, or a dash when it is empty.
func listOrDash(values []string) string {
	if len(values) == 0 {
		return dash
	}
	return strings.Join(values, ", ")
}

// textOrDash keeps a value, or a dash when it is empty.
func textOrDash(value string) string {
	if value == "" {
		return dash
	}
	return value
}

// yesNo renders a flag.
func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
