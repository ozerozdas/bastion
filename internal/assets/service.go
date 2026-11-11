// Package assets owns the assets bastion tracks, their scan history and the
// finding decisions attached to them (PROJECT_SPEC.md §5, §6).
//
// Assets are addressed by a stable id because a finding's fingerprint includes
// the asset id: archiving and reviving an asset keeps its id, so its history
// stays diffable. Scans run through jobs.Manager; this package only queues,
// reads and cancels them.
package assets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Scan limit bounds for the scan list.
const (
	// DefaultScanLimit is the page size when the caller does not ask for one.
	DefaultScanLimit = 50
	// MaxScanLimit caps one page, so a client cannot ask for the whole table.
	MaxScanLimit = 200
)

// ScanTriggerUI is the scans.trigger value for a scan queued from the UI/API.
const ScanTriggerUI = "ui"

var (
	// ErrNotFound means the asset or scan id does not exist.
	ErrNotFound = errors.New("assets: not found")
	// ErrConflict means the asset already exists or is archived.
	ErrConflict = errors.New("assets: conflict")
	// ErrInvalid marks input the service refuses before SQL; handlers map it to
	// HTTP 400.
	ErrInvalid = errors.New("assets: invalid input")
	// ErrNotActive means the scan is unknown, finished or already canceled.
	ErrNotActive = errors.New("assets: scan is not active")
	// ErrUnavailable means the server was built without a scan manager.
	ErrUnavailable = errors.New("assets: scan queue is not configured")
)

// TokenSource resolves GitHub credentials. *connections.Service implements it:
// ConnectionToken looks one connection up, Token is the default token.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	ConnectionToken(ctx context.Context, id int64) (string, error)
}

// RepoClient is the GitHub call asset creation needs. *github.Client
// implements it.
type RepoClient interface {
	Repo(ctx context.Context, owner, name string) (github.Repo, error)
}

// RepoClientFactory builds a client for a token. Tests inject a fake; serve
// passes one that carries the build version in the User-Agent.
type RepoClientFactory func(token string) (RepoClient, error)

// Option customises a Service. Tests use WithScanManager and WithGitHub.
type Option func(*Service)

// WithScanManager wires the queue POST /api/scans enqueues through.
func WithScanManager(manager *jobs.Manager) Option {
	return func(s *Service) {
		if manager != nil {
			s.manager = manager
		}
	}
}

// WithGitHub wires the credential lookup and client factory that resolve a
// repository's default branch when a repo asset is added.
func WithGitHub(factory RepoClientFactory, tokens TokenSource) Option {
	return func(s *Service) {
		if factory != nil {
			s.newRepoClient = factory
		}
		if tokens != nil {
			s.tokens = tokens
		}
	}
}

// Service implements the assets, scans and finding-state API. It is safe for
// concurrent use: *sql.DB is, and jobs.Manager is.
type Service struct {
	db            *sql.DB
	manager       *jobs.Manager
	newRepoClient RepoClientFactory
	tokens        TokenSource
	now           func() time.Time
}

// NewService validates its dependencies and returns a Service.
func NewService(db *sql.DB, opts ...Option) (*Service, error) {
	if db == nil {
		return nil, errors.New("assets: database is required")
	}
	s := &Service{db: db, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Asset is one tracked asset with the summary the API returns.
type Asset struct {
	ID             int64
	Kind           string
	ConnectionID   *int64
	DisplayName    string
	Ref            string
	DefaultBranch  string
	CreatedAt      time.Time
	LastScan       *LastScan
	OpenSeverities SeverityCounts
}

// LastScan is an asset's newest scan, whatever its status.
type LastScan struct {
	ScanID     int64
	Status     string
	FinishedAt *time.Time
}

// SeverityCounts are the open findings per severity of the asset's newest
// succeeded scan.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Scan is one scan row. ScannerRuns is filled by Scan (the single-scan read)
// only.
type Scan struct {
	ID          int64
	AssetID     int64
	TargetRef   string
	Status      string
	Trigger     string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	Error       string
	ScannerRuns []ScannerRun
}

// ScannerRun is one scanner's result inside a scan.
type ScannerRun struct {
	Scanner        string
	ScannerVersion string
	DBVersion      string
	Status         string
	DurationMS     *int64
	Error          string
}

// QueuedScan ties an enqueued scan id back to the asset it scans.
type QueuedScan struct {
	ScanID  int64
	AssetID int64
}

// CreateInput is one POST /api/assets request.
type CreateInput struct {
	Kind         string
	Ref          string
	ConnectionID int64
}

// FindingStateInput is one POST /api/findings/{fingerprint}/state request.
type FindingStateInput struct {
	AssetID     int64
	Fingerprint string
	State       string
	Reason      string
}

// List returns every non-archived asset with its newest scan and open severity
// counts.
func (s *Service) List(ctx context.Context) ([]Asset, error) {
	rows, err := sqlcdb.New(s.db).ListAssetSummaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("assets: list: %w", err)
	}
	out := make([]Asset, 0, len(rows))
	for _, row := range rows {
		out = append(out, assetSummary(row))
	}
	return out, nil
}

// Create tracks a repository or a local path. A repository's default branch is
// resolved through GitHub with the connection's token; a path must be an
// existing absolute directory. Re-adding an archived asset revives that row so
// its id, history and finding decisions survive.
func (s *Service) Create(ctx context.Context, in CreateInput) (Asset, error) {
	switch in.Kind {
	case string(findings.AssetKindRepo):
		return s.createRepo(ctx, in)
	case string(findings.AssetKindPath):
		return s.createPath(ctx, in)
	default:
		return Asset{}, fmt.Errorf("%w: kind %q is not one of %s, %s", ErrInvalid,
			in.Kind, findings.AssetKindRepo, findings.AssetKindPath)
	}
}

// createRepo validates owner/repo, rejects an existing asset before calling
// GitHub, then resolves the default branch and stores the asset.
func (s *Service) createRepo(ctx context.Context, in CreateInput) (Asset, error) {
	if in.ConnectionID < 0 {
		return Asset{}, fmt.Errorf("%w: connection_id must be positive", ErrInvalid)
	}
	ref, owner, name, err := parseRepoRef(in.Ref)
	if err != nil {
		return Asset{}, err
	}
	if existing, err := s.existing(ctx, string(findings.AssetKindRepo), ref); err != nil {
		return Asset{}, err
	} else if existing != nil && !existing.ArchivedAt.Valid {
		return Asset{}, fmt.Errorf("%w: repository %s is already tracked", ErrConflict, ref)
	}

	branch, err := s.defaultBranch(ctx, in.ConnectionID, ref, owner, name)
	if err != nil {
		return Asset{}, err
	}

	connectionID := sql.NullInt64{Int64: in.ConnectionID, Valid: in.ConnectionID > 0}
	return s.save(ctx, saveInput{
		kind:          string(findings.AssetKindRepo),
		ref:           ref,
		displayName:   ref,
		defaultBranch: sql.NullString{String: branch, Valid: branch != ""},
		connectionID:  connectionID,
	})
}

// createPath validates that ref is an existing absolute directory. The cleaned
// path is the asset's ref, so the same directory is never tracked twice.
func (s *Service) createPath(ctx context.Context, in CreateInput) (Asset, error) {
	ref := strings.TrimSpace(in.Ref)
	if ref == "" {
		return Asset{}, fmt.Errorf("%w: a path is required", ErrInvalid)
	}
	if !filepath.IsAbs(ref) {
		return Asset{}, fmt.Errorf("%w: path %q must be absolute", ErrInvalid, ref)
	}
	info, err := os.Stat(ref)
	if err != nil {
		return Asset{}, fmt.Errorf("%w: path %q does not exist or is not readable", ErrInvalid, ref)
	}
	if !info.IsDir() {
		return Asset{}, fmt.Errorf("%w: path %q is not a directory", ErrInvalid, ref)
	}
	ref = filepath.Clean(ref)

	if existing, err := s.existing(ctx, string(findings.AssetKindPath), ref); err != nil {
		return Asset{}, err
	} else if existing != nil && !existing.ArchivedAt.Valid {
		return Asset{}, fmt.Errorf("%w: path %s is already tracked", ErrConflict, ref)
	}
	return s.save(ctx, saveInput{
		kind:        string(findings.AssetKindPath),
		ref:         ref,
		displayName: filepath.Base(ref),
	})
}

// existing returns the asset row for kind+ref, or nil when there is none.
func (s *Service) existing(ctx context.Context, kind, ref string) (*sqlcdb.Asset, error) {
	row, err := sqlcdb.New(s.db).GetAssetByKindRef(ctx, sqlcdb.GetAssetByKindRefParams{Kind: kind, Ref: ref})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("assets: look up %s %q: %w", kind, ref, err)
	}
	return &row, nil
}

// defaultBranch resolves a repository's default branch through GitHub. The
// token comes from connectionID, or the default connection when it is zero.
func (s *Service) defaultBranch(ctx context.Context, connectionID int64, fullName, owner, name string) (string, error) {
	if s.tokens == nil || s.newRepoClient == nil {
		return "", fmt.Errorf("%w: GitHub is not configured; start bastion serve with its database", ErrUnavailable)
	}
	token, err := s.tokens.ConnectionToken(ctx, connectionID)
	if err != nil {
		return "", fmt.Errorf("assets: resolve default branch of %s: %w", fullName, err)
	}
	client, err := s.newRepoClient(token)
	if err != nil {
		return "", fmt.Errorf("assets: create GitHub client: %w", err)
	}
	repo, err := client.Repo(ctx, owner, name)
	if err != nil {
		return "", fmt.Errorf("assets: resolve default branch of %s: %w", fullName, err)
	}
	if repo.DefaultBranch == "" {
		return "", fmt.Errorf("%w: GitHub reports no default branch for %s", ErrInvalid, fullName)
	}
	return repo.DefaultBranch, nil
}

// saveInput is the resolved asset row to insert or revive.
type saveInput struct {
	kind          string
	ref           string
	displayName   string
	defaultBranch sql.NullString
	connectionID  sql.NullInt64
}

// save inserts the asset or, when the row exists but is archived, revives it.
// A concurrent create can still hit the unique constraint; that surfaces as a
// conflict rather than a 500.
func (s *Service) save(ctx context.Context, in saveInput) (Asset, error) {
	queries := sqlcdb.New(s.db)

	row, err := queries.GetAssetByKindRef(ctx, sqlcdb.GetAssetByKindRefParams{Kind: in.kind, Ref: in.ref})
	switch {
	case err == nil && !row.ArchivedAt.Valid:
		return Asset{}, fmt.Errorf("%w: %s %q is already tracked", ErrConflict, in.kind, in.ref)
	case err == nil:
		revived, err := queries.UnarchiveAsset(ctx, row.ID)
		if err != nil {
			return Asset{}, fmt.Errorf("assets: revive %s %q: %w", in.kind, in.ref, err)
		}
		return s.byID(ctx, revived.ID)
	case !errors.Is(err, sql.ErrNoRows):
		return Asset{}, fmt.Errorf("assets: look up %s %q: %w", in.kind, in.ref, err)
	}

	metadata := "{}"
	created, err := queries.CreateAsset(ctx, sqlcdb.CreateAssetParams{
		Kind:          in.kind,
		ConnectionID:  in.connectionID,
		DisplayName:   in.displayName,
		Ref:           in.ref,
		DefaultBranch: in.defaultBranch,
		MetadataJSON:  metadata,
		CreatedAt:     s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return Asset{}, fmt.Errorf("assets: create %s %q: %w", in.kind, in.ref, err)
	}
	return s.byID(ctx, created.ID)
}

// byID re-reads one asset through the summary list, so a create response
// carries the same fields as the list.
func (s *Service) byID(ctx context.Context, id int64) (Asset, error) {
	list, err := s.List(ctx)
	if err != nil {
		return Asset{}, err
	}
	for _, asset := range list {
		if asset.ID == id {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("%w: asset %d", ErrNotFound, id)
}

// Archive soft-deletes an asset: the row and its history stay, but it leaves
// the lists, the dashboard and new scans.
func (s *Service) Archive(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("%w: asset id must be positive", ErrInvalid)
	}
	_, err := sqlcdb.New(s.db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ArchivedAt: sql.NullString{String: s.now().UTC().Format(time.RFC3339), Valid: true},
		ID:         id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: asset %d", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("assets: archive %d: %w", id, err)
	}
	return nil
}

// Scans lists scans newest first, optionally narrowed to one asset. assetID 0
// means every asset; limit must be between 1 and MaxScanLimit.
func (s *Service) Scans(ctx context.Context, assetID int64, limit int) ([]Scan, error) {
	if assetID < 0 {
		return nil, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	if limit < 1 || limit > MaxScanLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, MaxScanLimit)
	}
	params := sqlcdb.ListScansParams{Limit: int64(limit)}
	if assetID > 0 {
		params.AssetID = assetID
	}
	rows, err := sqlcdb.New(s.db).ListScans(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("assets: list scans: %w", err)
	}
	out := make([]Scan, 0, len(rows))
	for _, row := range rows {
		scan, err := scanFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, scan)
	}
	return out, nil
}

// Scan reads one scan with its scanner runs.
func (s *Service) Scan(ctx context.Context, id int64) (Scan, error) {
	if id <= 0 {
		return Scan{}, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}
	queries := sqlcdb.New(s.db)
	row, err := queries.GetScan(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, fmt.Errorf("%w: scan %d", ErrNotFound, id)
	}
	if err != nil {
		return Scan{}, fmt.Errorf("assets: get scan %d: %w", id, err)
	}
	scan, err := scanFromRow(row)
	if err != nil {
		return Scan{}, err
	}

	runs, err := queries.ListScannerRunsByScan(ctx, id)
	if err != nil {
		return Scan{}, fmt.Errorf("assets: scan %d scanner runs: %w", id, err)
	}
	for _, run := range runs {
		item := ScannerRun{
			Scanner:        run.Scanner,
			ScannerVersion: run.ScannerVersion.String,
			DBVersion:      run.DBVersion.String,
			Status:         run.Status,
			Error:          run.Error.String,
		}
		if run.DurationMS.Valid {
			duration := run.DurationMS.Int64
			item.DurationMS = &duration
		}
		scan.ScannerRuns = append(scan.ScannerRuns, item)
	}
	return scan, nil
}

// Enqueue queues one scan per asset. Every id is validated first, so a bad id
// never leaves a partial batch in the queue.
func (s *Service) Enqueue(ctx context.Context, assetIDs []int64) ([]QueuedScan, error) {
	if len(assetIDs) == 0 {
		return nil, fmt.Errorf("%w: at least one asset id is required", ErrInvalid)
	}
	if s.manager == nil {
		return nil, fmt.Errorf("%w: start bastion serve with its database", ErrUnavailable)
	}

	queries := sqlcdb.New(s.db)
	seen := make(map[int64]struct{}, len(assetIDs))
	for _, id := range assetIDs {
		if id <= 0 {
			return nil, fmt.Errorf("%w: asset id %d must be positive", ErrInvalid, id)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		asset, err := queries.GetAsset(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: asset %d", ErrNotFound, id)
		}
		if err != nil {
			return nil, fmt.Errorf("assets: enqueue asset %d: %w", id, err)
		}
		if asset.ArchivedAt.Valid {
			return nil, fmt.Errorf("%w: asset %d is archived", ErrConflict, id)
		}
		seen[id] = struct{}{}
	}

	out := make([]QueuedScan, 0, len(seen))
	for _, id := range assetIDs {
		if len(out) > 0 {
			// Skip duplicates already queued in this batch.
			duplicate := false
			for _, queued := range out {
				if queued.AssetID == id {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
		}
		scanID, err := s.manager.Enqueue(ctx, id, ScanTriggerUI)
		if err != nil {
			if errors.Is(err, jobs.ErrShutdown) {
				return nil, fmt.Errorf("%w: the server is shutting down", ErrUnavailable)
			}
			return nil, fmt.Errorf("assets: enqueue asset %d: %w", id, err)
		}
		out = append(out, QueuedScan{ScanID: scanID, AssetID: id})
	}
	return out, nil
}

// Cancel stops a queued or running scan and returns the scan as it stands. A
// finished scan is a conflict, an unknown one is not found.
func (s *Service) Cancel(ctx context.Context, scanID int64) (Scan, error) {
	if scanID <= 0 {
		return Scan{}, fmt.Errorf("%w: scan id must be positive", ErrInvalid)
	}
	if _, err := s.Scan(ctx, scanID); err != nil {
		return Scan{}, err
	}
	if s.manager == nil {
		return Scan{}, fmt.Errorf("%w: start bastion serve with its database", ErrUnavailable)
	}
	if err := s.manager.Cancel(scanID); err != nil {
		if errors.Is(err, jobs.ErrScanNotActive) {
			return Scan{}, fmt.Errorf("%w: scan %d already finished", ErrNotActive, scanID)
		}
		return Scan{}, fmt.Errorf("assets: cancel scan %d: %w", scanID, err)
	}
	return s.Scan(ctx, scanID)
}

// SetFindingState records a decision for one fingerprint of one asset.
func (s *Service) SetFindingState(ctx context.Context, in FindingStateInput) error {
	if err := s.checkFindingStateInput(in); err != nil {
		return err
	}
	if err := s.requireAsset(ctx, in.AssetID); err != nil {
		return err
	}
	if err := store.SetFindingState(ctx, s.db, in.AssetID, in.Fingerprint, in.State, in.Reason); err != nil {
		return fmt.Errorf("assets: set finding state: %w", err)
	}
	return nil
}

// ClearFindingState removes the decision for one fingerprint of one asset.
// Clearing a decision that does not exist is not an error.
func (s *Service) ClearFindingState(ctx context.Context, assetID int64, fingerprint string) error {
	if assetID <= 0 {
		return fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	if strings.TrimSpace(fingerprint) == "" {
		return fmt.Errorf("%w: fingerprint is required", ErrInvalid)
	}
	if err := s.requireAsset(ctx, assetID); err != nil {
		return err
	}
	if err := store.ClearFindingState(ctx, s.db, assetID, fingerprint); err != nil {
		return fmt.Errorf("assets: clear finding state: %w", err)
	}
	return nil
}

// checkFindingStateInput rejects a decision the store would refuse, with a
// message that names the API fields.
func (s *Service) checkFindingStateInput(in FindingStateInput) error {
	if in.AssetID <= 0 {
		return fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	if strings.TrimSpace(in.Fingerprint) == "" {
		return fmt.Errorf("%w: fingerprint is required", ErrInvalid)
	}
	switch in.State {
	case store.FindingStateIgnored, store.FindingStateAcceptedRisk, store.FindingStateFalsePositive:
	default:
		return fmt.Errorf("%w: state %q is not one of %s, %s, %s", ErrInvalid, in.State,
			store.FindingStateIgnored, store.FindingStateAcceptedRisk, store.FindingStateFalsePositive)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return fmt.Errorf("%w: a reason is required, so a hidden finding stays reviewable", ErrInvalid)
	}
	return nil
}

// requireAsset reports whether the asset exists, archived or not.
func (s *Service) requireAsset(ctx context.Context, id int64) error {
	_, err := sqlcdb.New(s.db).GetAsset(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: asset %d", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("assets: look up asset %d: %w", id, err)
	}
	return nil
}

// parseRepoRef validates owner/name and returns the canonical ref and its
// parts. Repository names follow GitHub's own character set.
func parseRepoRef(value string) (ref, owner, name string, err error) {
	ref = strings.TrimSpace(value)
	owner, name, ok := strings.Cut(ref, "/")
	switch {
	case !ok || strings.Contains(name, "/"):
		return "", "", "", fmt.Errorf("%w: %q is not owner/name", ErrInvalid, value)
	case !validRepoSegment(owner) || !validRepoSegment(name):
		return "", "", "", fmt.Errorf("%w: %q has an invalid owner or repository name", ErrInvalid, value)
	}
	return owner + "/" + name, owner, name, nil
}

// validRepoSegment reports whether s can be a GitHub owner or repository name:
// letters, digits, ".", "_" and "-", at most 100 characters (GitHub's limit).
func validRepoSegment(s string) bool {
	if s == "" || len(s) > 100 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// assetSummary converts one summary row into the API shape.
func assetSummary(row sqlcdb.ListAssetSummariesRow) Asset {
	createdAt, _ := time.Parse(time.RFC3339, row.CreatedAt)
	asset := Asset{
		ID:            row.ID,
		Kind:          row.Kind,
		DisplayName:   row.DisplayName,
		Ref:           row.Ref,
		DefaultBranch: row.DefaultBranch.String,
		CreatedAt:     createdAt,
		OpenSeverities: SeverityCounts{
			Critical: int(row.OpenCritical),
			High:     int(row.OpenHigh),
			Medium:   int(row.OpenMedium),
			Low:      int(row.OpenLow),
			Unknown:  int(row.OpenUnknown),
		},
	}
	if row.ConnectionID.Valid {
		id := row.ConnectionID.Int64
		asset.ConnectionID = &id
	}
	if row.LastScanID.Valid {
		last := &LastScan{ScanID: row.LastScanID.Int64, Status: row.LastScanStatus.String}
		if finished, err := parseTimestamp(row.LastScanFinishedAt); err == nil {
			last.FinishedAt = finished
		}
		asset.LastScan = last
	}
	return asset
}

// scanFromRow converts one scans row into the API shape.
func scanFromRow(row sqlcdb.Scan) (Scan, error) {
	scan := Scan{
		ID:        row.ID,
		AssetID:   row.AssetID,
		TargetRef: row.TargetRef.String,
		Status:    row.Status,
		Trigger:   row.Trigger,
		Error:     row.Error.String,
	}
	started, err := parseTimestamp(row.StartedAt)
	if err != nil {
		return Scan{}, fmt.Errorf("assets: scan %d started_at: %w", row.ID, err)
	}
	scan.StartedAt = started
	finished, err := parseTimestamp(row.FinishedAt)
	if err != nil {
		return Scan{}, fmt.Errorf("assets: scan %d finished_at: %w", row.ID, err)
	}
	scan.FinishedAt = finished
	return scan, nil
}

// parseTimestamp decodes a stored RFC 3339 timestamp; NULL stays nil.
func parseTimestamp(value sql.NullString) (*time.Time, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
