package reports

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// SLA bounds. The threshold bounds match the database CHECK; the window bounds
// mirror the trend report's.
const (
	// MinSLAThresholdDays is the shortest allowed threshold.
	MinSLAThresholdDays = 1
	// MaxSLAThresholdDays is the longest allowed threshold.
	MaxSLAThresholdDays = 3650
	// DefaultSLAWindowDays is the fix window when the caller does not ask for
	// one.
	DefaultSLAWindowDays = 90
	// MaxSLAWindowDays caps the fix window, so one request cannot ask for
	// years.
	MaxSLAWindowDays = 365
)

// defaultSLAThresholds is the policy the migration seeds. It also fills a
// severity whose row is somehow missing, so a damaged table cannot make every
// finding of that severity overdue.
var defaultSLAThresholds = SLAThresholds{
	Critical: 7,
	High:     30,
	Medium:   90,
	Low:      180,
}

// SLAThresholds is the days a finding of each severity may stay open.
type SLAThresholds struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Validate rejects a threshold outside the allowed range.
func (t SLAThresholds) Validate() error {
	for _, item := range []struct {
		severity string
		days     int
	}{
		{severity: string(findings.SeverityCritical), days: t.Critical},
		{severity: string(findings.SeverityHigh), days: t.High},
		{severity: string(findings.SeverityMedium), days: t.Medium},
		{severity: string(findings.SeverityLow), days: t.Low},
	} {
		if item.days < MinSLAThresholdDays || item.days > MaxSLAThresholdDays {
			return fmt.Errorf("%w: %s must be between %d and %d days", ErrInvalid,
				item.severity, MinSLAThresholdDays, MaxSLAThresholdDays)
		}
	}
	return nil
}

// days returns the threshold for one severity and whether that severity has
// one. Unknown severity has none: the SLA report leaves it out.
func (t SLAThresholds) days(severity string) (int, bool) {
	switch findings.Severity(severity) {
	case findings.SeverityCritical:
		return t.Critical, true
	case findings.SeverityHigh:
		return t.High, true
	case findings.SeverityMedium:
		return t.Medium, true
	case findings.SeverityLow:
		return t.Low, true
	}
	return 0, false
}

// SLAOverdue is one open finding older than its severity's threshold.
type SLAOverdue struct {
	Finding       Finding
	FirstSeen     time.Time
	AgeDays       int
	ThresholdDays int
	OverdueDays   int
}

// SLAReport is everything GET /api/reports/sla returns.
type SLAReport struct {
	Thresholds   SLAThresholds
	Overdue      []SLAOverdue
	OpenCount    int
	OverdueCount int
	// FixedInWindow counts the fingerprints that disappeared and whose fix
	// date falls inside the window.
	FixedInWindow int
	// MeanTimeToFixDays averages fix date minus first appearance over the
	// findings fixed in the window; nil when none was.
	MeanTimeToFixDays *float64
}

// SLAThresholds reads the stored thresholds, filling a missing severity with
// the default.
func (s *Service) SLAThresholds(ctx context.Context) (SLAThresholds, error) {
	rows, err := sqlcdb.New(s.db).ListSLAThresholds(ctx)
	if err != nil {
		return SLAThresholds{}, fmt.Errorf("reports: sla thresholds: %w", err)
	}

	thresholds := defaultSLAThresholds
	for _, row := range rows {
		switch findings.Severity(row.Severity) {
		case findings.SeverityCritical:
			thresholds.Critical = int(row.Days)
		case findings.SeverityHigh:
			thresholds.High = int(row.Days)
		case findings.SeverityMedium:
			thresholds.Medium = int(row.Days)
		case findings.SeverityLow:
			thresholds.Low = int(row.Days)
		}
	}
	return thresholds, nil
}

// SetSLAThresholds validates and stores all four thresholds in one
// transaction, so a rejected value writes nothing.
func (s *Service) SetSLAThresholds(ctx context.Context, thresholds SLAThresholds) (SLAThresholds, error) {
	if err := thresholds.Validate(); err != nil {
		return SLAThresholds{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SLAThresholds{}, fmt.Errorf("reports: sla thresholds: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	for _, item := range []struct {
		severity string
		days     int
	}{
		{severity: string(findings.SeverityCritical), days: thresholds.Critical},
		{severity: string(findings.SeverityHigh), days: thresholds.High},
		{severity: string(findings.SeverityMedium), days: thresholds.Medium},
		{severity: string(findings.SeverityLow), days: thresholds.Low},
	} {
		if err := queries.UpsertSLAThreshold(ctx, sqlcdb.UpsertSLAThresholdParams{
			Severity: item.severity,
			Days:     int64(item.days),
		}); err != nil {
			return SLAThresholds{}, fmt.Errorf("reports: store %s threshold: %w", item.severity, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return SLAThresholds{}, fmt.Errorf("reports: sla thresholds: commit: %w", err)
	}
	return thresholds, nil
}

// SLA ages the latest open findings against the stored thresholds and reports
// the overdue ones plus the fix statistics of the window. The scope is the
// findings list's: non-archived assets, ignore decisions applied, licence
// "allow" findings hidden. days must be 1..MaxSLAWindowDays; the caller
// applies DefaultSLAWindowDays when the request omitted it.
func (s *Service) SLA(ctx context.Context, assetID int64, days int) (SLAReport, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return SLAReport{}, err
	}
	if days < 1 || days > MaxSLAWindowDays {
		return SLAReport{}, fmt.Errorf("%w: days must be between 1 and %d", ErrInvalid, MaxSLAWindowDays)
	}

	thresholds, err := s.SLAThresholds(ctx)
	if err != nil {
		return SLAReport{}, err
	}
	list, err := s.Findings(ctx, Filter{AssetID: assetID, Status: FindingStatusOpen})
	if err != nil {
		return SLAReport{}, err
	}

	var assetArg interface{}
	if assetID > 0 {
		assetArg = assetID
	}
	queries := sqlcdb.New(s.db)
	firstSeenRows, err := queries.SLAFirstSeen(ctx, assetArg)
	if err != nil {
		return SLAReport{}, fmt.Errorf("reports: sla first seen: %w", err)
	}
	firstSeen := make(map[int64]time.Time, len(firstSeenRows))
	for _, row := range firstSeenRows {
		seen, err := parseTimestamp(row.FirstSeenAt)
		if err != nil {
			return SLAReport{}, fmt.Errorf("reports: sla first seen of finding %d: %w", row.FindingID, err)
		}
		if seen != nil {
			firstSeen[row.FindingID] = *seen
		}
	}

	now := s.now().UTC()
	report := SLAReport{
		Thresholds: thresholds,
		Overdue:    make([]SLAOverdue, 0),
		OpenCount:  len(list),
	}
	for _, finding := range list {
		seen, ok := firstSeen[finding.ID]
		if !ok {
			// Without a first appearance the finding cannot be aged.
			continue
		}
		threshold, ok := thresholds.days(finding.Severity)
		if !ok {
			continue
		}
		age := wholeDays(now.Sub(seen))
		if age <= threshold {
			continue
		}
		report.Overdue = append(report.Overdue, SLAOverdue{
			Finding:       finding,
			FirstSeen:     seen.UTC(),
			AgeDays:       age,
			ThresholdDays: threshold,
			OverdueDays:   age - threshold,
		})
	}
	sort.SliceStable(report.Overdue, func(i, j int) bool {
		if left, right := report.Overdue[i].OverdueDays, report.Overdue[j].OverdueDays; left != right {
			return left > right
		}
		return report.Overdue[i].Finding.ID < report.Overdue[j].Finding.ID
	})
	report.OverdueCount = len(report.Overdue)

	fixedRows, err := queries.SLAFixedFindings(ctx, assetArg)
	if err != nil {
		return SLAReport{}, fmt.Errorf("reports: sla fixed findings: %w", err)
	}
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	var totalDays float64
	for _, row := range fixedRows {
		seen, err := parseTimestamp(row.FirstSeenAt)
		if err != nil {
			return SLAReport{}, fmt.Errorf("reports: sla fixed %s: first seen: %w", row.Fingerprint, err)
		}
		fixedAt, err := parseTimestamp(row.FixedAt)
		if err != nil {
			return SLAReport{}, fmt.Errorf("reports: sla fixed %s: fix date: %w", row.Fingerprint, err)
		}
		if seen == nil || fixedAt == nil {
			continue
		}
		if fixedAt.Before(since) || fixedAt.After(now) {
			continue
		}
		report.FixedInWindow++
		totalDays += fixedAt.Sub(*seen).Hours() / 24
	}
	if report.FixedInWindow > 0 {
		mean := totalDays / float64(report.FixedInWindow)
		report.MeanTimeToFixDays = &mean
	}
	return report, nil
}

// wholeDays is the number of complete days in a duration, never negative.
func wholeDays(d time.Duration) int {
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}
