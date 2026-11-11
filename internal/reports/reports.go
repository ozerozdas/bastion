// Package reports aggregates findings for the Dashboard (PROJECT_SPEC.md §6,
// §7.1) and backs the latest-findings list.
//
// Every aggregate counts only open findings of each non-archived asset's most
// recent succeeded scan: a failed, canceled or running scan never shadows the
// last complete report. A finding_states decision hides its finding everywhere;
// the queries compute the effective status exactly like the findings list.
// Because a decision is keyed on (asset_id, fingerprint) it also applies to
// scans older than the decision, so the trend shows what is open today, not
// what was open then — ignoring a finding removes it from past points too.
package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Service answers the report queries. It is safe for concurrent use: *sql.DB
// is.
type Service struct {
	db *sql.DB
}

// NewService validates its dependencies and returns a Service.
func NewService(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, errors.New("reports: database is required")
	}
	return &Service{db: db}, nil
}

// SeverityTotals is the open finding count per severity.
type SeverityTotals struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// TypeTotals is the open finding count per finding type (§5).
type TypeTotals struct {
	Vulnerability int
	Secret        int
	Outdated      int
	Misconfig     int
	License       int
	Malware       int
	SAST          int
}

// AssetRisk is one asset's open finding counts and its risk score
// (critical*1000 + high*100 + medium*10 + low).
type AssetRisk struct {
	AssetID     int64
	DisplayName string
	Kind        string
	Score       int
	Critical    int
	High        int
	Medium      int
	Low         int
}

// TrendScan is one point of an asset's trend: the open critical+high findings
// of one succeeded scan.
type TrendScan struct {
	ScanID           int64
	FinishedAt       *time.Time
	CriticalHighOpen int
}

// AssetTrend is the series of one asset, oldest scan first.
type AssetTrend struct {
	AssetID int64
	Scans   []TrendScan
}

// LastScan is the newest scan of one asset, whatever its status.
type LastScan struct {
	AssetID     int64
	DisplayName string
	ScanID      int64
	Status      string
	FinishedAt  *time.Time
}

// Dashboard is everything GET /api/reports/dashboard returns.
type Dashboard struct {
	TotalsBySeverity SeverityTotals
	TotalsByType     TypeTotals
	TopAssets        []AssetRisk
	Trend            []AssetTrend
	LastScans        []LastScan
}

// Dashboard computes the report aggregates in one pass over the database. The
// queries are independent, so a partially failed read reports an error rather
// than mixing stale and fresh numbers.
func (s *Service) Dashboard(ctx context.Context) (Dashboard, error) {
	queries := sqlcdb.New(s.db)

	severities, err := queries.ReportTotalsBySeverity(ctx)
	if err != nil {
		return Dashboard{}, fmt.Errorf("reports: totals by severity: %w", err)
	}
	types, err := queries.ReportTotalsByType(ctx)
	if err != nil {
		return Dashboard{}, fmt.Errorf("reports: totals by type: %w", err)
	}
	topAssets, err := queries.ReportTopAssets(ctx)
	if err != nil {
		return Dashboard{}, fmt.Errorf("reports: top assets: %w", err)
	}
	trendRows, err := queries.ReportTrendScans(ctx)
	if err != nil {
		return Dashboard{}, fmt.Errorf("reports: trend: %w", err)
	}
	lastScanRows, err := queries.ReportLastScans(ctx)
	if err != nil {
		return Dashboard{}, fmt.Errorf("reports: last scans: %w", err)
	}

	dashboard := Dashboard{
		TopAssets: make([]AssetRisk, 0, len(topAssets)),
		Trend:     make([]AssetTrend, 0),
		LastScans: make([]LastScan, 0, len(lastScanRows)),
	}

	for _, row := range severities {
		count := int(row.FindingCount)
		switch row.Severity {
		case string(findings.SeverityCritical):
			dashboard.TotalsBySeverity.Critical = count
		case string(findings.SeverityHigh):
			dashboard.TotalsBySeverity.High = count
		case string(findings.SeverityMedium):
			dashboard.TotalsBySeverity.Medium = count
		case string(findings.SeverityLow):
			dashboard.TotalsBySeverity.Low = count
		case string(findings.SeverityUnknown):
			dashboard.TotalsBySeverity.Unknown = count
		}
	}

	for _, row := range types {
		count := int(row.FindingCount)
		switch findings.Type(row.Type) {
		case findings.TypeVulnerability:
			dashboard.TotalsByType.Vulnerability = count
		case findings.TypeSecret:
			dashboard.TotalsByType.Secret = count
		case findings.TypeOutdated:
			dashboard.TotalsByType.Outdated = count
		case findings.TypeMisconfig:
			dashboard.TotalsByType.Misconfig = count
		case findings.TypeLicense:
			dashboard.TotalsByType.License = count
		case findings.TypeMalware:
			dashboard.TotalsByType.Malware = count
		case findings.TypeSAST:
			dashboard.TotalsByType.SAST = count
		}
	}

	for _, row := range topAssets {
		dashboard.TopAssets = append(dashboard.TopAssets, AssetRisk{
			AssetID:     row.AssetID,
			DisplayName: row.DisplayName,
			Kind:        row.Kind,
			Score:       int(row.Score),
			Critical:    int(row.Critical),
			High:        int(row.High),
			Medium:      int(row.Medium),
			Low:         int(row.Low),
		})
	}

	for _, row := range trendRows {
		if len(dashboard.Trend) == 0 || dashboard.Trend[len(dashboard.Trend)-1].AssetID != row.AssetID {
			dashboard.Trend = append(dashboard.Trend, AssetTrend{AssetID: row.AssetID})
		}
		finishedAt, err := parseTimestamp(row.FinishedAt)
		if err != nil {
			return Dashboard{}, fmt.Errorf("reports: trend scan %d: %w", row.ScanID, err)
		}
		asset := &dashboard.Trend[len(dashboard.Trend)-1]
		asset.Scans = append(asset.Scans, TrendScan{
			ScanID:           row.ScanID,
			FinishedAt:       finishedAt,
			CriticalHighOpen: int(row.CriticalHighOpen),
		})
	}

	for _, row := range lastScanRows {
		finishedAt, err := parseTimestamp(row.FinishedAt)
		if err != nil {
			return Dashboard{}, fmt.Errorf("reports: last scan %d: %w", row.ScanID, err)
		}
		dashboard.LastScans = append(dashboard.LastScans, LastScan{
			AssetID:     row.AssetID,
			DisplayName: row.DisplayName,
			ScanID:      row.ScanID,
			Status:      row.Status,
			FinishedAt:  finishedAt,
		})
	}

	return dashboard, nil
}

// parseTimestamp reads a stored RFC3339 timestamp; a NULL column stays a nil
// time, which the API omits.
func parseTimestamp(value sql.NullString) (*time.Time, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value.String)
	if err != nil {
		return nil, fmt.Errorf("parse timestamp %q: %w", value.String, err)
	}
	return &parsed, nil
}
