package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Finding status values (findings.status and the effective status the API
// reports). Any finding_states decision reports a finding as ignored.
const (
	FindingStatusOpen    = "open"
	FindingStatusIgnored = "ignored"
)

// ErrInvalid marks a filter the service refuses; handlers map it to HTTP 400.
var ErrInvalid = errors.New("reports: invalid filter")

// Filter narrows the latest-findings list. The zero value means every asset and
// every enum value; AssetID 0 means "all assets".
type Filter struct {
	AssetID  int64
	Severity string
	Type     string
	Status   string
}

// Finding is one normalized finding of an asset's latest succeeded scan. Unset
// optional fields stay empty strings, so the API can omit them.
type Finding struct {
	ID              int64
	AssetID         int64
	ScanID          int64
	Fingerprint     string
	Type            string
	Severity        string
	Title           string
	RuleID          string
	PackageName     string
	PackageVersion  string
	FixedVersion    string
	Ecosystem       string
	Location        string
	Occurrences     int
	Scanner         string
	Status          string
	State           string
	Reason          string
	FirstSeenScanID *int64
	Description     string
	References      []string
}

// Findings lists the findings of the most recent succeeded scan of every
// non-archived asset, most severe first, with the effective status: a
// finding_states decision for the same asset and fingerprint reports the
// finding as ignored and fills State and Reason.
func (s *Service) Findings(ctx context.Context, filter Filter) ([]Finding, error) {
	params, err := filter.params()
	if err != nil {
		return nil, err
	}

	rows, err := sqlcdb.New(s.db).ListLatestFindings(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("reports: list findings: %w", err)
	}

	out := make([]Finding, 0, len(rows))
	for _, row := range rows {
		references, err := decodeReferences(row.ReferencesJSON)
		if err != nil {
			return nil, fmt.Errorf("reports: finding %d: %w", row.ID, err)
		}
		finding := Finding{
			ID:             row.ID,
			AssetID:        row.AssetID,
			ScanID:         row.ScanID,
			Fingerprint:    row.Fingerprint,
			Type:           row.Type,
			Severity:       row.Severity,
			Title:          row.Title,
			RuleID:         row.RuleID.String,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			Ecosystem:      row.Ecosystem.String,
			Location:       row.Location.String,
			Occurrences:    int(row.Occurrences),
			Scanner:        row.Scanner,
			Status:         row.Status,
			State:          row.State.String,
			Reason:         row.Reason.String,
			Description:    row.Description.String,
			References:     references,
		}
		if row.FirstSeenScanID.Valid {
			firstSeen := row.FirstSeenScanID.Int64
			finding.FirstSeenScanID = &firstSeen
		}
		out = append(out, finding)
	}
	return out, nil
}

// params validates the filter and converts it to the query's nullable
// arguments: a nil interface means "no filter" in ListLatestFindings.
func (f Filter) params() (sqlcdb.ListLatestFindingsParams, error) {
	var params sqlcdb.ListLatestFindingsParams

	if f.AssetID < 0 {
		return params, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	if f.AssetID > 0 {
		params.AssetID = f.AssetID
	}

	if err := validateEnums(f.Severity, f.Type, f.Status); err != nil {
		return params, err
	}
	params.Severity = nullable(f.Severity)
	params.Type = nullable(f.Type)
	params.Status = nullable(f.Status)

	return params, nil
}

// validateEnums rejects an enum value no filter accepts. The message names the
// rejected value, because the caller sees it as a problem detail.
func validateEnums(severity, kind, status string) error {
	if severity != "" && !validSeverity(severity) {
		return fmt.Errorf("%w: severity %q is not one of %s, %s, %s, %s, %s", ErrInvalid,
			severity, findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
			findings.SeverityLow, findings.SeverityUnknown)
	}
	if kind != "" && !validType(kind) {
		return fmt.Errorf("%w: type %q is not one of %s, %s, %s, %s, %s, %s, %s", ErrInvalid,
			kind, findings.TypeVulnerability, findings.TypeSecret, findings.TypeOutdated,
			findings.TypeMisconfig, findings.TypeLicense, findings.TypeMalware, findings.TypeSAST)
	}
	if status != "" && status != FindingStatusOpen && status != FindingStatusIgnored {
		return fmt.Errorf("%w: status %q is not one of %s, %s", ErrInvalid,
			status, FindingStatusOpen, FindingStatusIgnored)
	}
	return nil
}

// nullable turns an empty filter value into a nil query argument, which the
// generated SQL reads as "no filter".
func nullable(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func validSeverity(severity string) bool {
	switch findings.Severity(severity) {
	case findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
		findings.SeverityLow, findings.SeverityUnknown:
		return true
	}
	return false
}

func validType(kind string) bool {
	switch findings.Type(kind) {
	case findings.TypeVulnerability, findings.TypeSecret, findings.TypeOutdated,
		findings.TypeMisconfig, findings.TypeLicense, findings.TypeMalware, findings.TypeSAST:
		return true
	}
	return false
}

// decodeReferences reads the stored references_json list. An absent or empty
// column is an empty list, never nil, so the API always serializes [].
func decodeReferences(raw string) ([]string, error) {
	references := make([]string, 0)
	if raw == "" {
		return references, nil
	}
	if err := json.Unmarshal([]byte(raw), &references); err != nil {
		return nil, fmt.Errorf("decode references %q: %w", raw, err)
	}
	if references == nil {
		references = make([]string, 0)
	}
	return references, nil
}
