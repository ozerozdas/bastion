package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Final scan statuses (PROJECT_SPEC.md §5 scans.status). queued and running are
// intermediate: StartScan queues a scan, MarkScanRunning moves it on.
const (
	ScanStatusSucceeded = "succeeded"
	ScanStatusFailed    = "failed"
	ScanStatusCanceled  = "canceled"
)

// ScanTriggerCLI is the scans.trigger value for a scan started from the CLI.
const ScanTriggerCLI = "cli"

// scanStatusQueued is the state StartScan creates a scan in.
const scanStatusQueued = "queued"

// GetOrCreateAsset resolves the asset a scan targets and returns it with its
// real id, creating the row the first time the target is seen. A repeat target
// keeps its id, which matters because fingerprints include it (PROJECT_SPEC.md
// §5): a scan that does not use the stored id can never be diffed. The id on
// asset is ignored.
func GetOrCreateAsset(ctx context.Context, db *sql.DB, asset findings.Asset) (findings.Asset, error) {
	if db == nil {
		return findings.Asset{}, errors.New("store: get or create asset: database is required")
	}
	if asset.Kind == "" || asset.Ref == "" {
		return findings.Asset{}, errors.New("store: get or create asset: kind and ref are required")
	}

	row, err := sqlcdb.New(db).GetOrCreateAsset(ctx, sqlcdb.GetOrCreateAssetParams{
		Kind:         string(asset.Kind),
		DisplayName:  asset.DisplayName,
		Ref:          asset.Ref,
		MetadataJSON: "{}",
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return findings.Asset{}, fmt.Errorf("store: get or create asset %s %q: %w", asset.Kind, asset.Ref, err)
	}

	return findings.Asset{
		ID:          row.ID,
		Kind:        findings.AssetKind(row.Kind),
		DisplayName: row.DisplayName,
		Ref:         row.Ref,
	}, nil
}

// StartScan queues a scan of assetID with the given trigger and returns its id.
// The scan stays queued until MarkScanRunning, so a crash between the two
// leaves a visible queued scan rather than a phantom running one.
func StartScan(ctx context.Context, db *sql.DB, assetID int64, trigger string) (int64, error) {
	if db == nil {
		return 0, errors.New("store: start scan: database is required")
	}

	scan, err := sqlcdb.New(db).CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: assetID,
		Status:  scanStatusQueued,
		Trigger: trigger,
	})
	if err != nil {
		return 0, fmt.Errorf("store: start scan for asset %d: %w", assetID, err)
	}
	return scan.ID, nil
}

// MarkScanRunning records that the scanners of a queued scan are about to
// start. A later call keeps the first started_at.
func MarkScanRunning(ctx context.Context, db *sql.DB, scanID int64) error {
	if db == nil {
		return errors.New("store: mark scan running: database is required")
	}

	err := sqlcdb.New(db).MarkScanRunning(ctx, sqlcdb.MarkScanRunningParams{
		StartedAt: nullString(time.Now().UTC().Format(time.RFC3339)),
		ID:        scanID,
	})
	if err != nil {
		return fmt.Errorf("store: mark scan %d running: %w", scanID, err)
	}
	return nil
}

// ScannerRun is one scanner's result inside a scan (§5 scanner_runs). The
// unset strings and the nil duration are stored as NULL.
type ScannerRun struct {
	Scanner        string
	ScannerVersion string
	DBVersion      string
	Status         string
	DurationMS     *int64
	Error          string
	RawPath        string
}

// ScanResult is everything one finished scan produced. Callers build it from
// their scanner output (cmd/bastion/scan.go's scanOutput) and hand it to
// SaveScanResult once the scan is over, successful or not.
type ScanResult struct {
	// Status is the final state: succeeded, failed or canceled. A failed scan
	// still persists its partial results.
	Status string
	// TargetRef is the resolved git SHA or image digest, stored when set. An
	// empty value keeps the ref the scan was created with.
	TargetRef string
	// Error is the failure message for a failed scan; empty stores NULL.
	Error string
	// FinishedAt defaults to now (UTC) when zero.
	FinishedAt time.Time

	ScannerRuns []ScannerRun
	Packages    []findings.Package
	Findings    []findings.Finding
}

// SaveScanResult persists one finished scan in a single transaction: the final
// scan state, its scanner_runs, its SBOM packages and its findings. Either
// every row lands or none does, so a crash or a constraint violation never
// leaves a half-written scan behind.
//
// The scan row must already exist (CreateScan). Findings belong to the scan's
// asset; a finding's AssetID is ignored, because the stored value must match
// the scan even when a caller left it unset. An empty fingerprint is rejected:
// without one a finding cannot be diffed against later scans.
func SaveScanResult(ctx context.Context, db *sql.DB, scanID int64, res ScanResult) error {
	if db == nil {
		return errors.New("store: save scan: database is required")
	}
	if err := validateScanResult(res); err != nil {
		return err
	}

	finishedAt := res.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}
	finished := finishedAt.UTC().Format(time.RFC3339)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: save scan %d: begin transaction: %w", scanID, err)
	}
	// A rollback after a successful commit is a no-op; the error is not
	// actionable either way.
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	scan, err := queries.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("store: save scan %d: load scan: %w", scanID, err)
	}

	for _, run := range res.ScannerRuns {
		if err := queries.InsertScannerRun(ctx, newScannerRunParams(scanID, run)); err != nil {
			return fmt.Errorf("store: save scan %d: scanner run %q: %w", scanID, run.Scanner, err)
		}
	}

	for _, pkg := range res.Packages {
		if err := queries.InsertPackage(ctx, newPackageParams(scanID, pkg)); err != nil {
			return fmt.Errorf("store: save scan %d: package %q: %w", scanID, pkg.Name, err)
		}
	}

	for _, f := range res.Findings {
		firstSeen, err := queries.EarliestScanIDForFingerprint(ctx, sqlcdb.EarliestScanIDForFingerprintParams{
			AssetID:     scan.AssetID,
			Fingerprint: f.Fingerprint,
		})
		if err != nil {
			return fmt.Errorf("store: save scan %d: first seen of %s: %w", scanID, f.Fingerprint, err)
		}
		// The fingerprint was not stored before: this scan is where it appears.
		if firstSeen == 0 {
			firstSeen = scanID
		}
		params, err := newFindingParams(scanID, scan.AssetID, firstSeen, f, finished)
		if err != nil {
			return fmt.Errorf("store: save scan %d: finding %q: %w", scanID, f.Title, err)
		}
		if err := queries.InsertFinding(ctx, params); err != nil {
			return fmt.Errorf("store: save scan %d: finding %q: %w", scanID, f.Title, err)
		}
	}

	if err := queries.FinishScan(ctx, sqlcdb.FinishScanParams{
		Status:     res.Status,
		FinishedAt: nullString(finished),
		Error:      nullString(res.Error),
		TargetRef:  nullString(res.TargetRef),
		ID:         scanID,
	}); err != nil {
		return fmt.Errorf("store: save scan %d: finish scan: %w", scanID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: save scan %d: commit: %w", scanID, err)
	}
	return nil
}

// validateScanResult rejects input the schema would refuse, before a
// transaction is opened, so the caller gets a message that names the culprit.
func validateScanResult(res ScanResult) error {
	switch res.Status {
	case ScanStatusSucceeded, ScanStatusFailed, ScanStatusCanceled:
	default:
		return fmt.Errorf("store: save scan: status %q is not final (want succeeded, failed or canceled)", res.Status)
	}
	for _, f := range res.Findings {
		if f.Fingerprint == "" {
			return fmt.Errorf("store: save scan: finding %q has no fingerprint", f.Title)
		}
	}
	return nil
}

func newScannerRunParams(scanID int64, run ScannerRun) sqlcdb.InsertScannerRunParams {
	return sqlcdb.InsertScannerRunParams{
		ScanID:         scanID,
		Scanner:        run.Scanner,
		ScannerVersion: nullString(run.ScannerVersion),
		DBVersion:      nullString(run.DBVersion),
		Status:         run.Status,
		DurationMS:     nullInt64(run.DurationMS),
		Error:          nullString(run.Error),
		RawPath:        nullString(run.RawPath),
	}
}

func newPackageParams(scanID int64, pkg findings.Package) sqlcdb.InsertPackageParams {
	params := sqlcdb.InsertPackageParams{
		ScanID:    scanID,
		Ecosystem: pkg.Ecosystem,
		Name:      pkg.Name,
		Version:   nullString(pkg.Version),
		PURL:      nullString(pkg.PURL),
		Path:      nullString(pkg.Path),
	}
	if pkg.Direct != nil {
		direct := int64(0)
		if *pkg.Direct {
			direct = 1
		}
		params.Direct = sql.NullInt64{Int64: direct, Valid: true}
	}
	return params
}

func newFindingParams(scanID, assetID, firstSeen int64, f findings.Finding, createdAt string) (sqlcdb.InsertFindingParams, error) {
	references, err := referencesJSON(f.References)
	if err != nil {
		return sqlcdb.InsertFindingParams{}, err
	}
	occurrences := int64(f.Occurrences)
	if occurrences < 1 {
		// One finding per fingerprint per scan; a caller that does not merge
		// still means "seen once".
		occurrences = 1
	}
	params := sqlcdb.InsertFindingParams{
		ScanID:          scanID,
		AssetID:         assetID,
		Type:            string(f.Type),
		Fingerprint:     f.Fingerprint,
		Occurrences:     occurrences,
		Severity:        string(f.Severity),
		Title:           f.Title,
		RuleID:          nullString(f.RuleID),
		PackageName:     nullString(f.PackageName),
		PackageVersion:  nullString(f.PackageVersion),
		FixedVersion:    nullString(f.FixedVersion),
		Ecosystem:       nullString(f.Ecosystem),
		Location:        nullString(f.Location),
		Description:     nullString(f.Description),
		ReferencesJSON:  references,
		Scanner:         f.Scanner,
		FirstSeenScanID: sql.NullInt64{Int64: firstSeen, Valid: true},
		CreatedAt:       createdAt,
	}
	if f.CVSS != nil {
		params.CVSS = sql.NullFloat64{Float64: *f.CVSS, Valid: true}
	}
	return params, nil
}

// referencesJSON encodes the reference list. An absent list is stored as []
// rather than NULL, matching the column default.
func referencesJSON(refs []string) (string, error) {
	if len(refs) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return "", fmt.Errorf("encode references: %w", err)
	}
	return string(encoded), nil
}

// nullString stores an empty Go string as SQL NULL, the representation every
// other table uses for "unknown" (PROJECT_SPEC.md §5).
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullInt64 stores a nil pointer as SQL NULL.
func nullInt64(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}
