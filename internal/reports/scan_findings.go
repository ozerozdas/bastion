package reports

import (
	"context"
	"fmt"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// ScanFilter narrows the findings of one scan. The zero value keeps every enum
// value.
type ScanFilter struct {
	Type     string
	Severity string
	Status   string
}

// ScanFindings lists every finding one scan produced, most severe first, with
// the effective status: a finding_states decision for the same asset and
// fingerprint reports the finding as ignored and fills State and Reason.
func (s *Service) ScanFindings(ctx context.Context, scanID int64, filter ScanFilter) ([]Finding, error) {
	if scanID <= 0 {
		return nil, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}
	params, err := filter.params(scanID)
	if err != nil {
		return nil, err
	}

	rows, err := sqlcdb.New(s.db).ListFindingsByScan(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("reports: list findings of scan %d: %w", scanID, err)
	}

	out := make([]Finding, 0, len(rows))
	for _, row := range rows {
		finding, err := findingFromScanRow(row)
		if err != nil {
			return nil, fmt.Errorf("reports: finding %d of scan %d: %w", row.ID, scanID, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// params validates the filter and converts it to the query's nullable
// arguments: a nil interface means "no filter" in ListFindingsByScan.
func (f ScanFilter) params(scanID int64) (sqlcdb.ListFindingsByScanParams, error) {
	params := sqlcdb.ListFindingsByScanParams{ScanID: scanID}
	if err := validateEnums(f.Severity, f.Type, f.Status); err != nil {
		return params, err
	}
	if f.Severity != "" {
		params.Severity = f.Severity
	}
	if f.Type != "" {
		params.Type = f.Type
	}
	if f.Status != "" {
		params.Status = f.Status
	}
	return params, nil
}

// findingFromScanRow converts one ListFindingsByScan row into the read model.
// The columns mirror ListLatestFindings', so the two conversions stay parallel.
func findingFromScanRow(row sqlcdb.ListFindingsByScanRow) (Finding, error) {
	references, err := decodeReferences(row.ReferencesJSON)
	if err != nil {
		return Finding{}, err
	}
	scanners, err := decodeScanners(row.Scanners)
	if err != nil {
		return Finding{}, err
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
		Scanners:       scanners,
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
	return finding, nil
}
