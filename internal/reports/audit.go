package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// MaxAuditFindings caps the findings an audit pack carries. The summary still
// counts every finding in scope; only the list is cut.
const MaxAuditFindings = MaxFindingLimit

// AuditAsset is the asset an audit pack was requested for.
type AuditAsset struct {
	ID          int64
	DisplayName string
	Kind        string
}

// AuditSummary counts the findings in scope per effective severity. Total
// counts them all, including those dropped from Findings by the cap.
type AuditSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	Total    int
}

// AuditReport is everything GET /api/reports/audit returns.
type AuditReport struct {
	GeneratedAt time.Time
	// Asset is nil when the pack covers the whole fleet.
	Asset     *AuditAsset
	Summary   AuditSummary
	Findings  []Finding
	FixPlan   fixplan.Plan
	Truncated bool
}

// Audit composes one audit pack: the findings list, its severity summary and
// the fix plan. The scope is the findings list's (newest succeeded scan of
// every non-archived asset, ignore decisions applied); assetID 0 means every
// asset, and an unknown asset is ErrNotFound. findings are capped at
// MaxAuditFindings, most severe first, and the fix plan is empty without an
// asset.
func (s *Service) Audit(ctx context.Context, assetID int64) (AuditReport, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return AuditReport{}, err
	}

	report := AuditReport{
		GeneratedAt: s.now().UTC(),
		Findings:    make([]Finding, 0),
		FixPlan: fixplan.Plan{
			Steps: make([]fixplan.Step, 0),
			NoFix: make([]fixplan.NoFix, 0),
		},
	}

	if assetID > 0 {
		asset, err := sqlcdb.New(s.db).GetAsset(ctx, assetID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return AuditReport{}, fmt.Errorf("%w: asset %d", ErrNotFound, assetID)
			}
			return AuditReport{}, fmt.Errorf("reports: look up asset %d: %w", assetID, err)
		}
		report.Asset = &AuditAsset{
			ID:          asset.ID,
			DisplayName: asset.DisplayName,
			Kind:        asset.Kind,
		}
	}

	list, err := s.Findings(ctx, Filter{AssetID: assetID, Status: FindingStatusOpen})
	if err != nil {
		return AuditReport{}, err
	}
	for _, finding := range list {
		report.Summary.Total++
		switch findings.Severity(finding.Severity) {
		case findings.SeverityCritical:
			report.Summary.Critical++
		case findings.SeverityHigh:
			report.Summary.High++
		case findings.SeverityMedium:
			report.Summary.Medium++
		case findings.SeverityLow:
			report.Summary.Low++
		default:
			report.Summary.Unknown++
		}
	}
	if len(list) > MaxAuditFindings {
		list = list[:MaxAuditFindings]
		report.Truncated = true
	}
	report.Findings = append(report.Findings, list...)

	if assetID > 0 {
		plan, err := s.FixPlan(ctx, assetID)
		if err != nil {
			return AuditReport{}, err
		}
		report.FixPlan = plan
	}
	return report, nil
}
