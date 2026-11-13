package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// findingStatusOpen is the effective status of a finding without an ignore
// decision (PROJECT_SPEC.md §5). ListFindingsByScan filters on it.
const findingStatusOpen = "open"

// GetOrCreateRepoAsset resolves the repository asset a repo scan targets,
// keyed on owner/name, and records the repository's default branch. A repeat
// scan keeps the row and id, which findings fingerprints depend on
// (PROJECT_SPEC.md §5). The id on the returned asset is the stored one.
func GetOrCreateRepoAsset(ctx context.Context, db *sql.DB, fullName, defaultBranch string) (findings.Asset, error) {
	if db == nil {
		return findings.Asset{}, errors.New("store: get or create repo asset: database is required")
	}
	if strings.TrimSpace(fullName) == "" {
		return findings.Asset{}, errors.New("store: get or create repo asset: owner/name is required")
	}

	row, err := sqlcdb.New(db).GetOrCreateAsset(ctx, sqlcdb.GetOrCreateAssetParams{
		Kind:          string(findings.AssetKindRepo),
		DisplayName:   fullName,
		Ref:           fullName,
		DefaultBranch: nullString(defaultBranch),
		MetadataJSON:  "{}",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return findings.Asset{}, fmt.Errorf("store: get or create repo asset %q: %w", fullName, err)
	}

	return findings.Asset{
		ID:          row.ID,
		Kind:        findings.AssetKind(row.Kind),
		DisplayName: row.DisplayName,
		Ref:         row.Ref,
	}, nil
}

// ScanReport is one persisted scan read back with everything the CLI prints
// about it. The CLI scans through jobs.Manager and then reports what the
// database holds, so output and stored state cannot disagree.
type ScanReport struct {
	ScanID int64
	Status string
	Error  string
	// TargetRef is the resolved git SHA or image digest, when the scan
	// resolved one.
	TargetRef   string
	ScannerRuns []ScannerRun
	Packages    []findings.Package
	// Findings are every finding of the scan, ignored ones included: they are
	// part of what the scan produced.
	Findings []findings.Finding
	// Open are the findings with no ignore decision. A severity gate such as
	// --fail-on must only consider these.
	Open []findings.Finding
}

// LoadScanReport reads a finished scan back from the database. The scan row
// must exist; a scan that never finished is reported as it currently stands.
func LoadScanReport(ctx context.Context, db *sql.DB, scanID int64) (ScanReport, error) {
	if db == nil {
		return ScanReport{}, errors.New("store: load scan report: database is required")
	}

	queries := sqlcdb.New(db)
	scan, err := queries.GetScan(ctx, scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanReport{}, fmt.Errorf("store: load scan report: scan %d does not exist", scanID)
	}
	if err != nil {
		return ScanReport{}, fmt.Errorf("store: load scan report %d: %w", scanID, err)
	}

	report := ScanReport{ScanID: scan.ID, Status: scan.Status}
	if scan.Error.Valid {
		report.Error = scan.Error.String
	}
	if scan.TargetRef.Valid {
		report.TargetRef = scan.TargetRef.String
	}

	runs, err := queries.ListScannerRunsByScan(ctx, scanID)
	if err != nil {
		return ScanReport{}, fmt.Errorf("store: load scan report %d: scanner runs: %w", scanID, err)
	}
	for _, run := range runs {
		report.ScannerRuns = append(report.ScannerRuns, ScannerRun{
			Scanner:        run.Scanner,
			ScannerVersion: run.ScannerVersion.String,
			DBVersion:      run.DBVersion.String,
			Status:         run.Status,
			DurationMS:     nullInt64Ptr(run.DurationMS),
			Error:          run.Error.String,
			RawPath:        run.RawPath.String,
		})
	}

	pkgs, err := queries.ListPackagesByScan(ctx, scanID)
	if err != nil {
		return ScanReport{}, fmt.Errorf("store: load scan report %d: packages: %w", scanID, err)
	}
	for _, pkg := range pkgs {
		report.Packages = append(report.Packages, findings.Package{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version.String,
			PURL:      pkg.PURL.String,
			Path:      pkg.Path.String,
			Direct:    nullDirectPtr(pkg.Direct),
		})
	}

	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scanID})
	if err != nil {
		return ScanReport{}, fmt.Errorf("store: load scan report %d: findings: %w", scanID, err)
	}
	for _, row := range rows {
		f, err := findingFromRow(row)
		if err != nil {
			return ScanReport{}, fmt.Errorf("store: load scan report %d: %w", scanID, err)
		}
		report.Findings = append(report.Findings, f)
	}

	open, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID: scanID,
		Status: findingStatusOpen,
	})
	if err != nil {
		return ScanReport{}, fmt.Errorf("store: load scan report %d: open findings: %w", scanID, err)
	}
	for _, row := range open {
		f, err := findingFromRow(row)
		if err != nil {
			return ScanReport{}, fmt.Errorf("store: load scan report %d: %w", scanID, err)
		}
		report.Open = append(report.Open, f)
	}

	return report, nil
}

// findingFromRow converts a stored finding row back into the normalized model.
// match and secret_hmac are deliberately absent from the schema (PROJECT_SPEC.md
// §5); a stored finding never carries them.
func findingFromRow(row sqlcdb.ListFindingsByScanRow) (findings.Finding, error) {
	refs, err := decodeReferences(row.ReferencesJSON)
	if err != nil {
		return findings.Finding{}, fmt.Errorf("finding %q references: %w", row.Title, err)
	}
	scanners, err := decodeStringList(row.Scanners)
	if err != nil {
		return findings.Finding{}, fmt.Errorf("finding %q scanners: %w", row.Title, err)
	}
	f := findings.Finding{
		AssetID:        row.AssetID,
		Type:           findings.Type(row.Type),
		RuleID:         row.RuleID.String,
		Severity:       findings.Severity(row.Severity),
		Title:          row.Title,
		PackageName:    row.PackageName.String,
		PackageVersion: row.PackageVersion.String,
		FixedVersion:   row.FixedVersion.String,
		Ecosystem:      row.Ecosystem.String,
		Location:       row.Location.String,
		Description:    row.Description.String,
		References:     refs,
		Scanner:        row.Scanner,
		Scanners:       scanners,
		Fingerprint:    row.Fingerprint,
		Occurrences:    int(row.Occurrences),
	}
	if row.CVSS.Valid {
		cvss := row.CVSS.Float64
		f.CVSS = &cvss
	}
	return f, nil
}

// decodeReferences decodes the stored reference list. The column default is
// "[]", so an empty list becomes nil and stays out of the printed document.
func decodeReferences(raw string) ([]string, error) {
	return decodeStringList(raw)
}

// decodeStringList decodes a JSON string array column. The column default is
// "[]", so an empty list becomes nil.
func decodeStringList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// nullInt64Ptr converts a nullable column back into an optional int.
func nullInt64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// nullDirectPtr converts the nullable packages.direct 0/1 column back into an
// optional bool.
func nullDirectPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}
