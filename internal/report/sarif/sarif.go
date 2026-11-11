// Package sarif renders bastion findings as a SARIF 2.1.0 log
// (PROJECT_SPEC.md §8 Phase 1, E7). The document uses only the fields GitHub
// code scanning needs: one run, one tool driver with a rule per rule id, and
// one result per finding with a relative artifact location and bastion's
// fingerprint.
package sarif

import (
	"strconv"
	"strings"

	"github.com/ozerozdas/bastion/internal/findings"
)

const (
	// Version is the SARIF version this package emits.
	Version = "2.1.0"
	// SchemaURI is the published SARIF 2.1.0 JSON schema.
	SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	// FingerprintKey namespaces bastion's partial fingerprint, so the value is
	// not confused with another tool's fingerprint for the same finding.
	FingerprintKey = "bastion/v1"
	// ToolName is the tool driver name GitHub shows for these results.
	ToolName = "bastion"
)

// Result levels (SARIF level property).
const (
	levelError   = "error"
	levelWarning = "warning"
	levelNote    = "note"
)

// Report is a SARIF 2.1.0 log with exactly one run.
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool invocation. bastion emits one run per scan.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the producing tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the tool driver. Rules are unique by id: GitHub shows one alert
// rule per entry.
type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Rules   []Rule `json:"rules"`
}

// Rule is one rule a result refers to.
type Rule struct {
	ID               string  `json:"id"`
	ShortDescription Message `json:"shortDescription"`
}

// Message is a SARIF message object.
type Message struct {
	Text string `json:"text"`
}

// Result is one finding.
type Result struct {
	RuleID    string  `json:"ruleId,omitempty"`
	RuleIndex *int    `json:"ruleIndex,omitempty"`
	Level     string  `json:"level"`
	Message   Message `json:"message"`
	// Locations is omitted for findings without a location (image package
	// findings may have one; a scanner may report neither).
	Locations []Location `json:"locations,omitempty"`
	// PartialFingerprints carries bastion's fingerprint, which is stable
	// across scans and lets GitHub track one alert over time.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// Location is the place a result was found.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is a file, and a line when the location names one.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a path relative to the scanned root: findings never
// carry the workspace directory, so the uri is already repository-relative.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is the line a finding starts on. SARIF requires startLine to be at
// least 1, so a finding without a line omits the region entirely.
type Region struct {
	StartLine int `json:"startLine"`
}

// Build renders list as a SARIF log for one scan. toolVersion is bastion's
// build version ("dev" when built from source). The caller passes findings in
// its display order; rules follow the order they first appear in.
func Build(toolVersion string, list []findings.Finding) Report {
	driver := Driver{Name: ToolName, Version: toolVersion}
	rules := make(map[string]int)
	results := make([]Result, 0, len(list))

	for _, f := range list {
		result := Result{
			Level:               level(f.Severity),
			Message:             Message{Text: messageText(f)},
			PartialFingerprints: map[string]string{FingerprintKey: f.Fingerprint},
		}
		if f.RuleID != "" {
			result.RuleID = f.RuleID
			index, ok := rules[f.RuleID]
			if !ok {
				index = len(driver.Rules)
				rules[f.RuleID] = index
				driver.Rules = append(driver.Rules, Rule{
					ID:               f.RuleID,
					ShortDescription: Message{Text: f.Title},
				})
			}
			result.RuleIndex = &index
		}
		if loc, ok := location(f.Location); ok {
			result.Locations = []Location{{PhysicalLocation: loc}}
		}
		results = append(results, result)
	}

	return Report{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{{
			Tool:    Tool{Driver: driver},
			Results: results,
		}},
	}
}

// level maps bastion's severity scale onto the three SARIF levels. Unknown
// severities are notes rather than errors: they must not fail a build.
func level(severity findings.Severity) string {
	switch severity {
	case findings.SeverityCritical, findings.SeverityHigh:
		return levelError
	case findings.SeverityMedium:
		return levelWarning
	default:
		return levelNote
	}
}

// messageText is the finding's title, with the package it belongs to when the
// scanner named one.
func messageText(f findings.Finding) string {
	switch {
	case f.Title == "" && f.RuleID != "":
		return f.RuleID
	case f.Title == "":
		return string(f.Type)
	case f.PackageName == "":
		return f.Title
	case f.PackageVersion == "":
		return f.Title + " (" + f.PackageName + ")"
	default:
		return f.Title + " (" + f.PackageName + "@" + f.PackageVersion + ")"
	}
}

// location turns a finding location into a physical location. A location is
// "file", "file:line" or a scanner-specific string such as a misconfiguration's
// "file#resource"; only a numeric suffix is read as a line.
func location(location string) (PhysicalLocation, bool) {
	file, line := splitLocation(location)
	if file == "" {
		return PhysicalLocation{}, false
	}
	loc := PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: file}}
	if line > 0 {
		loc.Region = &Region{StartLine: line}
	}
	return loc, true
}

// splitLocation splits "file:line" into its file part and line number. Without
// a numeric suffix the whole location is the file and the line is 0.
func splitLocation(location string) (string, int) {
	loc := strings.TrimSpace(location)
	file := loc
	line := 0
	if i := strings.LastIndex(loc, ":"); i > 0 {
		if n, err := strconv.Atoi(loc[i+1:]); err == nil && n > 0 {
			file, line = loc[:i], n
		}
	}
	file = strings.ReplaceAll(file, "\\", "/")
	file = strings.TrimPrefix(file, "./")
	return file, line
}
