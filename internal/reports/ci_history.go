package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// CI history bounds.
const (
	// DefaultCIHistoryLimit is the number of runs returned when the caller does
	// not ask for one.
	DefaultCIHistoryLimit = 50
	// MaxCIHistoryLimit caps one response.
	MaxCIHistoryLimit = 200
)

// CI history trigger values a caller may filter by.
const (
	CIHistoryTriggerUI  = "ui"
	CIHistoryTriggerCLI = "cli"
	CIHistoryTriggerAPI = "api"
)

// validCIHistoryTrigger reports whether a trigger filter is acceptable; the
// empty string means every trigger.
func validCIHistoryTrigger(trigger string) bool {
	switch trigger {
	case "", CIHistoryTriggerUI, CIHistoryTriggerCLI, CIHistoryTriggerAPI:
		return true
	}
	return false
}

// CIScannerRun is one scanner's outcome within a CI run.
type CIScannerRun struct {
	Scanner string
	Status  string
}

// CIRun is one scan the history lists.
type CIRun struct {
	ScanID      int64
	AssetID     int64
	DisplayName string
	Trigger     string
	Status      string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	// DurationMS is finish minus start, nil while either is missing.
	DurationMS *int
	// Counts is the scan's findings per raw severity. Ignored findings are
	// counted and no licence policy applies.
	Counts   SeverityTotals
	Scanners []CIScannerRun
}

// CIHistoryReport is everything GET /api/reports/ci-history returns.
type CIHistoryReport struct {
	Runs []CIRun
}

// CIHistory lists the latest scans, newest first, across every non-archived
// asset or only assetID when it is positive. trigger narrows the list to one
// of ui, cli or api; the empty string lists every trigger. limit must be
// 1..MaxCIHistoryLimit; the caller applies DefaultCIHistoryLimit when the
// request omitted it.
func (s *Service) CIHistory(ctx context.Context, assetID int64, trigger string, limit int) (CIHistoryReport, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return CIHistoryReport{}, err
	}
	if !validCIHistoryTrigger(trigger) {
		return CIHistoryReport{}, fmt.Errorf("%w: trigger must be ui, cli or api", ErrInvalid)
	}
	if limit < 1 || limit > MaxCIHistoryLimit {
		return CIHistoryReport{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, MaxCIHistoryLimit)
	}

	params := sqlcdb.ReportCIHistoryParams{RunLimit: int64(limit)}
	scannerParams := sqlcdb.ReportCIScannerRunsParams{RunLimit: int64(limit)}
	if assetID > 0 {
		params.AssetID = assetID
		scannerParams.AssetID = assetID
	}
	if trigger != "" {
		params.Trigger = trigger
		scannerParams.Trigger = trigger
	}

	rows, err := sqlcdb.New(s.db).ReportCIHistory(ctx, params)
	if err != nil {
		return CIHistoryReport{}, fmt.Errorf("reports: ci history: %w", err)
	}
	scannerRows, err := sqlcdb.New(s.db).ReportCIScannerRuns(ctx, scannerParams)
	if err != nil {
		return CIHistoryReport{}, fmt.Errorf("reports: ci scanner runs: %w", err)
	}
	scanners := make(map[int64][]CIScannerRun, len(scannerRows))
	for _, row := range scannerRows {
		scanners[row.ScanID] = append(scanners[row.ScanID], CIScannerRun{
			Scanner: row.Scanner,
			Status:  row.Status,
		})
	}

	runs := make([]CIRun, 0, len(rows))
	for _, row := range rows {
		started, err := parseTimestamp(row.StartedAt)
		if err != nil {
			return CIHistoryReport{}, fmt.Errorf("reports: ci run %d: started_at: %w", row.ScanID, err)
		}
		finished, err := parseTimestamp(row.FinishedAt)
		if err != nil {
			return CIHistoryReport{}, fmt.Errorf("reports: ci run %d: finished_at: %w", row.ScanID, err)
		}

		run := CIRun{
			ScanID:      row.ScanID,
			AssetID:     row.AssetID,
			DisplayName: row.DisplayName,
			Trigger:     row.Trigger,
			Status:      row.Status,
			StartedAt:   started,
			FinishedAt:  finished,
			Counts: SeverityTotals{
				Critical: int(row.Critical),
				High:     int(row.High),
				Medium:   int(row.Medium),
				Low:      int(row.Low),
				Unknown:  int(row.Unknown),
			},
			Scanners: scanners[row.ScanID],
		}
		if run.Scanners == nil {
			run.Scanners = make([]CIScannerRun, 0)
		}
		if started != nil && finished != nil {
			if elapsed := finished.Sub(*started); elapsed >= 0 {
				ms := int(elapsed.Milliseconds())
				run.DurationMS = &ms
			}
		}
		runs = append(runs, run)
	}
	return CIHistoryReport{Runs: runs}, nil
}
