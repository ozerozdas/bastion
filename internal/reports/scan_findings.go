package reports

import (
	"context"
	"fmt"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// ScanFilter narrows the findings of one scan. The zero value keeps every enum
// value.
type ScanFilter struct {
	Type     string
	Severity string
	Status   string
}

// ScanFindingPage is one window of a scan's findings. The endpoint has no page
// size, so Findings runs from Offset to the end; Total counts every matching
// finding.
type ScanFindingPage struct {
	Findings []Finding
	Total    int
}

// ScanFindings lists every finding one scan produced, most severe first, with
// the effective status: a finding_states decision for the same asset and
// fingerprint reports the finding as ignored and fills State and Reason.
func (s *Service) ScanFindings(ctx context.Context, scanID int64, filter ScanFilter) ([]Finding, error) {
	return s.scanFindings(ctx, scanID, filter, allRows, 0)
}

// ScanFindingsPage lists a scan's findings from offset, with the number of
// findings the filters match before the offset.
func (s *Service) ScanFindingsPage(ctx context.Context, scanID int64, filter ScanFilter, offset int) (ScanFindingPage, error) {
	if offset < 0 {
		return ScanFindingPage{}, fmt.Errorf("%w: offset must be 0 or greater", ErrInvalid)
	}
	if scanID <= 0 {
		return ScanFindingPage{}, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}

	countParams, err := filter.countParams(scanID, s.expiryNow())
	if err != nil {
		return ScanFindingPage{}, err
	}
	total, err := sqlcdb.New(s.db).CountFindingsByScanFiltered(ctx, countParams)
	if err != nil {
		return ScanFindingPage{}, fmt.Errorf("reports: count findings of scan %d: %w", scanID, err)
	}

	findings, err := s.scanFindings(ctx, scanID, filter, allRows, int64(offset))
	if err != nil {
		return ScanFindingPage{}, err
	}
	return ScanFindingPage{Findings: findings, Total: int(total)}, nil
}

// scanFindings reads one scan's findings with the window limit and offset.
func (s *Service) scanFindings(ctx context.Context, scanID int64, filter ScanFilter, limit, offset int64) ([]Finding, error) {
	if scanID <= 0 {
		return nil, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}
	params, err := filter.params(scanID, s.expiryNow(), limit, offset)
	if err != nil {
		return nil, err
	}

	rows, err := sqlcdb.New(s.db).ListFindingsByScan(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("reports: list findings of scan %d: %w", scanID, err)
	}

	out := make([]Finding, 0, len(rows))
	for _, row := range rows {
		finding, err := s.findingFromScanRow(row)
		if err != nil {
			return nil, fmt.Errorf("reports: finding %d of scan %d: %w", row.ID, scanID, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// params validates the filter and converts it to the query's nullable
// arguments: a nil interface means "no filter" in ListFindingsByScan. now is
// the clock the query compares a decision's expiry with.
func (f ScanFilter) params(scanID int64, now string, limit, offset int64) (sqlcdb.ListFindingsByScanParams, error) {
	params := sqlcdb.ListFindingsByScanParams{ScanID: scanID, Now: now, Limit: limit, Offset: offset}
	if err := f.validate(); err != nil {
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

// countParams converts the filter to CountFindingsByScanFiltered's arguments,
// which mirror ListFindingsByScan's filters without the window.
func (f ScanFilter) countParams(scanID int64, now string) (sqlcdb.CountFindingsByScanFilteredParams, error) {
	params := sqlcdb.CountFindingsByScanFilteredParams{ScanID: scanID, Now: now}
	if err := f.validate(); err != nil {
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

// validate rejects an enum value no filter accepts.
func (f ScanFilter) validate() error {
	return validateEnums(f.Severity, f.Type, f.Status)
}

// findingFromScanRow converts one ListFindingsByScan row into the read model.
// The columns mirror ListLatestFindings', so the two conversions stay parallel.
func (s *Service) findingFromScanRow(row sqlcdb.ListFindingsByScanRow) (Finding, error) {
	references, err := decodeReferences(row.ReferencesJSON)
	if err != nil {
		return Finding{}, err
	}
	scanners, err := decodeScanners(row.Scanners)
	if err != nil {
		return Finding{}, err
	}
	cwe, err := decodeCWE(row.CWE)
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
		CWE:            cwe,
		Status:         row.Status,
		State:          row.State.String,
		Reason:         row.Reason.String,
		DecidedBy:      row.DecidedBy.String,
		RuleRef:        row.RuleRef.Int64,
		ExpiresAt:      row.ExpiresAt.String,
		Expired:        row.Expired != 0,
		Description:    row.Description.String,
		References:     references,
		Reachability:   findings.Reachability(row.Reachability.String),
		LicencePolicy:  licencePolicyValue(row.LicencePolicy),
	}
	if row.FirstSeenScanID.Valid {
		firstSeen := row.FirstSeenScanID.Int64
		finding.FirstSeenScanID = &firstSeen
	}
	s.enrich(&finding)
	return finding, nil
}
