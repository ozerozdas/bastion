package reports

import (
	"context"
	"fmt"
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
	// MaxSLAOverdue caps the overdue list one response carries. OverdueCount
	// still reports how many entries the list holds, and OverdueTruncated says
	// the cap dropped some.
	MaxSLAOverdue = 500
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
	// OverdueTruncated says the overdue list hit MaxSLAOverdue and more
	// findings are overdue.
	OverdueTruncated bool
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

	now := s.now().UTC()
	nowText := s.expiryNow()
	var assetArg interface{}
	if assetID > 0 {
		assetArg = assetID
	}
	queries := sqlcdb.New(s.db)

	// The fleet-wide open count is a COUNT, not the decoded findings list: the
	// SLA report never needs every row to count them.
	countParams, err := (Filter{AssetID: assetID, Status: FindingStatusOpen}).countParams(nowText)
	if err != nil {
		return SLAReport{}, err
	}
	openCount, err := queries.CountLatestFindings(ctx, countParams)
	if err != nil {
		return SLAReport{}, fmt.Errorf("reports: sla open count: %w", err)
	}

	// Overdue rows are ranked and capped in SQL, so only the entries the
	// response can carry are decoded.
	overdueRows, err := queries.SLAOverdueFindings(ctx, sqlcdb.SLAOverdueFindingsParams{
		Now:      nowText,
		AssetID:  assetArg,
		RowLimit: MaxSLAOverdue + 1,
	})
	if err != nil {
		return SLAReport{}, fmt.Errorf("reports: sla overdue findings: %w", err)
	}

	report := SLAReport{
		Thresholds: thresholds,
		Overdue:    make([]SLAOverdue, 0),
		OpenCount:  int(openCount),
	}
	for _, row := range overdueRows {
		seen, err := parseTimestamp(row.FirstSeenAt)
		if err != nil {
			return SLAReport{}, fmt.Errorf("reports: sla finding %d: first seen: %w", row.ID, err)
		}
		if seen == nil {
			continue
		}
		threshold := int(row.ThresholdDays)
		age := wholeDays(now.Sub(*seen))
		if age <= threshold {
			// The SQL bound over-includes the exact threshold; the whole-day
			// age decides, exactly like the response's age_days.
			continue
		}
		if len(report.Overdue) == MaxSLAOverdue {
			report.OverdueTruncated = true
			break
		}
		finding, err := s.findingFromSLARow(row)
		if err != nil {
			return SLAReport{}, fmt.Errorf("reports: sla finding %d: %w", row.ID, err)
		}
		report.Overdue = append(report.Overdue, SLAOverdue{
			Finding:       finding,
			FirstSeen:     seen.UTC(),
			AgeDays:       age,
			ThresholdDays: threshold,
			OverdueDays:   age - threshold,
		})
	}
	report.OverdueCount = len(report.Overdue)

	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	fixedRows, err := queries.SLAFixedFindings(ctx, sqlcdb.SLAFixedFindingsParams{
		AssetID:     assetArg,
		WindowStart: since.UTC().Format(time.RFC3339),
		Now:         nowText,
	})
	if err != nil {
		return SLAReport{}, fmt.Errorf("reports: sla fixed findings: %w", err)
	}
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

// findingFromSLARow converts one SLAOverdueFindings row into the read model.
// The finding columns mirror ListLatestFindings', so the conversions stay
// parallel.
func (s *Service) findingFromSLARow(row sqlcdb.SLAOverdueFindingsRow) (Finding, error) {
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
		State:          row.State,
		Reason:         row.Reason.String,
		DecidedBy:      row.DecidedBy,
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

// wholeDays is the number of complete days in a duration, never negative.
func wholeDays(d time.Duration) int {
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}
