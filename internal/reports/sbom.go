package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/sbom"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// ScanSBOM builds the CycloneDX BOM of one succeeded scan from the package
// inventory it persisted. The order mirrors ScanDiff: an unknown scan is
// ErrNotFound, a scan without a complete result is ErrConflict, and the
// document's timestamp defaults to the scan's finish time so a stored scan
// always yields the same BOM.
func (s *Service) ScanSBOM(ctx context.Context, scanID int64, opts sbom.Options) (sbom.Document, error) {
	if scanID <= 0 {
		return sbom.Document{}, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}

	queries := sqlcdb.New(s.db)
	scan, err := queries.GetScan(ctx, scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return sbom.Document{}, fmt.Errorf("%w: scan %d", ErrNotFound, scanID)
	}
	if err != nil {
		return sbom.Document{}, fmt.Errorf("reports: sbom scan %d: %w", scanID, err)
	}
	if scan.Status != scanStatusSucceeded {
		return sbom.Document{}, fmt.Errorf("%w: scan %d is %s; only a succeeded scan has an SBOM",
			ErrConflict, scanID, scan.Status)
	}

	assetRow, err := queries.GetAsset(ctx, scan.AssetID)
	if errors.Is(err, sql.ErrNoRows) {
		return sbom.Document{}, fmt.Errorf("%w: asset %d of scan %d", ErrNotFound, scan.AssetID, scanID)
	}
	if err != nil {
		return sbom.Document{}, fmt.Errorf("reports: sbom scan %d: asset: %w", scanID, err)
	}

	rows, err := queries.ListPackagesByScan(ctx, scanID)
	if err != nil {
		return sbom.Document{}, fmt.Errorf("reports: sbom scan %d: packages: %w", scanID, err)
	}
	packages := make([]findings.Package, 0, len(rows))
	for _, row := range rows {
		packages = append(packages, findings.Package{
			Ecosystem: row.Ecosystem,
			Name:      row.Name,
			Version:   row.Version.String,
			PURL:      row.PURL.String,
			Path:      row.Path.String,
		})
	}

	if opts.Timestamp.IsZero() && scan.FinishedAt.Valid {
		if finished, err := time.Parse(time.RFC3339, scan.FinishedAt.String); err == nil {
			opts.Timestamp = finished
		}
	}

	asset := findings.Asset{
		ID:          assetRow.ID,
		Kind:        findings.AssetKind(assetRow.Kind),
		DisplayName: assetRow.DisplayName,
		Ref:         assetRow.Ref,
	}
	return sbom.Build(asset, packages, opts), nil
}
