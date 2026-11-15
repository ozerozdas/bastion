package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
	for _, row := range rows {
		inputs = append(inputs, fixplan.Input{
			ID:             row.ID,
			Ecosystem:      row.Ecosystem.String,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			Severity:       findings.Severity(row.Severity),
		})
	}
	return fixplan.Build(inputs), nil
}
