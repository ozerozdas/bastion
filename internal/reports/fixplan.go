package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// FixPlan groups one asset's open vulnerability findings into package upgrades
// (PROJECT_SPEC.md §7.2, §8 Phase 3). It reuses the findings list's "open"
// semantics: the asset's most recent succeeded scan, with any finding_states
// decision excluded. An unknown asset is ErrNotFound.
func (s *Service) FixPlan(ctx context.Context, assetID int64) (fixplan.Plan, error) {
	if assetID <= 0 {
		return fixplan.Plan{}, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}

	queries := sqlcdb.New(s.db)
	if _, err := queries.GetAsset(ctx, assetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fixplan.Plan{}, fmt.Errorf("%w: asset %d", ErrNotFound, assetID)
		}
		return fixplan.Plan{}, fmt.Errorf("reports: look up asset %d: %w", assetID, err)
	}

	rows, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{
		AssetID: assetID,
		Type:    string(findings.TypeVulnerability),
		Status:  FindingStatusOpen,
	})
	if err != nil {
		return fixplan.Plan{}, fmt.Errorf("reports: list findings for fix plan: %w", err)
	}

	inputs := make([]fixplan.Input, 0, len(rows))
	scores := make(map[int64]epss.Score, len(rows))
	for _, row := range rows {
		inputs = append(inputs, fixplan.Input{
			ID:             row.ID,
			Ecosystem:      row.Ecosystem.String,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			Severity:       findings.Severity(row.Severity),
		})
		if s.epss != nil && row.RuleID.String != "" {
			if score, ok := s.epss.Lookup(row.RuleID.String); ok {
				scores[row.ID] = score
			}
		}
	}

	plan := fixplan.Build(inputs)
	for i := range plan.Steps {
		plan.Steps[i].MaxEPSS = maxScore(plan.Steps[i].FindingIDs, scores)
	}
	return plan, nil
}

// maxScore returns the highest EPSS score among the given findings, keeping its
// percentile. It returns nil when none of them has a score.
func maxScore(ids []int64, scores map[int64]epss.Score) *epss.Score {
	var highest *epss.Score
	for _, id := range ids {
		score, ok := scores[id]
		if !ok {
			continue
		}
		if highest == nil || score.Score > highest.Score {
			value := score
			highest = &value
		}
	}
	return highest
}
