package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// ErrNotFound marks a scan id a diff cannot find; handlers map it to HTTP 404.
var ErrNotFound = errors.New("reports: not found")

// ErrConflict marks a scan a diff cannot use; handlers map it to HTTP 409.
var ErrConflict = errors.New("reports: conflict")

// scanStatusSucceeded is the only scans.status a diff accepts: a queued,
// running, failed or canceled scan has no complete finding set.
const scanStatusSucceeded = "succeeded"

// ScanDiff is the change in findings between two scans of one asset. AgainstScanID
// is nil when the asset has no earlier succeeded scan to compare with.
type ScanDiff struct {
	ScanID        int64
	AgainstScanID *int64
	// New and Persisting come from ScanID; Fixed comes from AgainstScanID.
	New        []Finding
	Fixed      []Finding
	Persisting []Finding
	Counts     ScanDiffCounts
}

// ScanDiffCounts is the number of findings per severity in each diff group.
type ScanDiffCounts struct {
	New        SeverityTotals
	Fixed      SeverityTotals
	Persisting SeverityTotals
}

// ScanDiff compares scanID with againstID, or with the newest succeeded scan of
// the same asset older than scanID when againstID is 0. Both scans must exist,
// must have succeeded and must belong to the same asset. A scan with nothing to
// compare against reports every finding as new.
//
// Findings are matched by fingerprint. The scans are read with ScanFindings, so
// each group keeps the findings list order: most severe first, then fingerprint.
func (s *Service) ScanDiff(ctx context.Context, scanID, againstID int64) (ScanDiff, error) {
	if scanID <= 0 {
		return ScanDiff{}, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}
	if againstID < 0 {
		return ScanDiff{}, fmt.Errorf("%w: against scan id must be positive", ErrInvalid)
	}
	if againstID == scanID {
		return ScanDiff{}, fmt.Errorf("%w: scan %d cannot be diffed against itself", ErrInvalid, scanID)
	}

	queries := sqlcdb.New(s.db)
	scan, err := queries.GetScan(ctx, scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanDiff{}, fmt.Errorf("%w: scan %d", ErrNotFound, scanID)
	}
	if err != nil {
		return ScanDiff{}, fmt.Errorf("reports: diff scan %d: %w", scanID, err)
	}
	if scan.Status != scanStatusSucceeded {
		return ScanDiff{}, fmt.Errorf("%w: scan %d is %s; only a succeeded scan can be diffed",
			ErrConflict, scanID, scan.Status)
	}

	against, err := s.diffBaseline(ctx, queries, scan, againstID)
	if err != nil {
		return ScanDiff{}, err
	}

	current, err := s.ScanFindings(ctx, scanID, ScanFilter{})
	if err != nil {
		return ScanDiff{}, err
	}
	if against == 0 {
		return ScanDiff{
			ScanID: scanID,
			New:    current,
			Counts: ScanDiffCounts{New: severityTotals(current)},
		}, nil
	}

	previous, err := s.ScanFindings(ctx, against, ScanFilter{})
	if err != nil {
		return ScanDiff{}, err
	}
	compared := findings.CompareBy(previous, current, func(f Finding) string { return f.Fingerprint })
	return ScanDiff{
		ScanID:        scanID,
		AgainstScanID: &against,
		New:           compared.New,
		Fixed:         compared.Fixed,
		Persisting:    compared.Persisting,
		Counts: ScanDiffCounts{
			New:        severityTotals(compared.New),
			Fixed:      severityTotals(compared.Fixed),
			Persisting: severityTotals(compared.Persisting),
		},
	}, nil
}

// diffBaseline resolves the scan a diff compares against. againstID 0 asks for
// the newest succeeded scan of scan's asset older than scan; 0 then means there
// is none. The explicit path validates the requested scan.
func (s *Service) diffBaseline(ctx context.Context, queries *sqlcdb.Queries, scan sqlcdb.Scan, againstID int64) (int64, error) {
	if againstID > 0 {
		other, err := queries.GetScan(ctx, againstID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return 0, fmt.Errorf("%w: scan %d", ErrNotFound, againstID)
		case err != nil:
			return 0, fmt.Errorf("reports: diff against scan %d: %w", againstID, err)
		case other.AssetID != scan.AssetID:
			return 0, fmt.Errorf("%w: scan %d and scan %d are scans of different assets",
				ErrInvalid, scan.ID, againstID)
		case other.Status != scanStatusSucceeded:
			return 0, fmt.Errorf("%w: scan %d is %s; only a succeeded scan can be diffed",
				ErrConflict, againstID, other.Status)
		}
		return againstID, nil
	}

	previous, err := queries.GetPreviousSucceededScan(ctx, sqlcdb.GetPreviousSucceededScanParams{
		AssetID: scan.AssetID,
		ID:      scan.ID,
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("reports: previous scan of asset %d before scan %d: %w",
			scan.AssetID, scan.ID, err)
	}
	return previous.ID, nil
}

// severityTotals counts findings per severity.
func severityTotals(list []Finding) SeverityTotals {
	var totals SeverityTotals
	for _, finding := range list {
		switch findings.Severity(finding.Severity) {
		case findings.SeverityCritical:
			totals.Critical++
		case findings.SeverityHigh:
			totals.High++
		case findings.SeverityMedium:
			totals.Medium++
		case findings.SeverityLow:
			totals.Low++
		case findings.SeverityUnknown:
			totals.Unknown++
		}
	}
	return totals
}
