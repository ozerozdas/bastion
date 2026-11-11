package jobs_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// openTestDB opens a fresh migrated database in a temporary directory, the way
// internal/store's own tests do.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bastion.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("store.Open(%q): %v", path, err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	return db
}

// createAsset inserts a path asset the scan jobs can target.
func createAsset(t *testing.T, db *sql.DB, kind, ref string) sqlcdb.Asset {
	t.Helper()

	asset, err := sqlcdb.New(db).GetOrCreateAsset(context.Background(), sqlcdb.GetOrCreateAssetParams{
		Kind:         kind,
		DisplayName:  ref,
		Ref:          ref,
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-11T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(%q): %v", ref, err)
	}
	return asset
}

// newManager starts a Manager and shuts it down when the test ends.
func newManager(t *testing.T, cfg jobs.Config) *jobs.Manager {
	t.Helper()

	m, err := jobs.New(cfg)
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return m
}

// waitForStatus polls until the scan reaches want, then returns the row.
func waitForStatus(t *testing.T, db *sql.DB, scanID int64, want string) sqlcdb.Scan {
	t.Helper()

	waitFor(t, "scan status "+want, func() bool {
		row, err := sqlcdb.New(db).GetScan(context.Background(), scanID)
		if err != nil {
			t.Fatalf("GetScan(%d): %v", scanID, err)
		}
		return row.Status == want
	})
	row, err := sqlcdb.New(db).GetScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScan(%d): %v", scanID, err)
	}
	return row
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeSource records fetches and hands back a workspace whose Cleanup counts
// calls.
type fakeSource struct {
	kind    sources.TargetKind
	mu      sync.Mutex
	fetched []string
	cleanup atomic.Int32
}

func (f *fakeSource) Kind() sources.TargetKind { return f.kind }

func (f *fakeSource) Fetch(ctx context.Context, target sources.Target) (*sources.Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.fetched = append(f.fetched, target.Ref)
	f.mu.Unlock()
	return &sources.Workspace{
		Dir:     target.Ref,
		Cleanup: func() error { f.cleanup.Add(1); return nil },
	}, nil
}

func (f *fakeSource) fetchedRefs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.fetched)
}

// fakeScanner is a Scanner whose Scan is supplied by the test. It always
// implements jobs.SerialScanner; serialized decides whether the pool locks it.
type fakeScanner struct {
	name       string
	kinds      []sources.TargetKind
	serialized bool
	scan       func(ctx context.Context, ws *sources.Workspace, opts scanners.Options) (*scanners.RawResult, error)
}

func (f *fakeScanner) Name() string    { return f.name }
func (f *fakeScanner) Version() string { return "test-1" }
func (f *fakeScanner) Supports(k sources.TargetKind) bool {
	return slices.Contains(f.kinds, k)
}
func (f *fakeScanner) Serialized() bool { return f.serialized }
func (f *fakeScanner) Scan(ctx context.Context, ws *sources.Workspace, opts scanners.Options) (*scanners.RawResult, error) {
	if f.scan == nil {
		return rawResult(f.name), nil
	}
	return f.scan(ctx, ws, opts)
}

func rawResult(name string) *scanners.RawResult {
	return &scanners.RawResult{Scanner: name, Version: "test-1", Raw: json.RawMessage(`{}`)}
}

// fakeNormalizer returns the configured findings and stamps the fingerprint a
// real normalizer would set.
type fakeNormalizer struct {
	items []findings.Finding
	pkgs  []findings.Package
	err   error
}

func (n *fakeNormalizer) Normalize(raw *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	if n.err != nil {
		return nil, nil, n.err
	}
	out := make([]findings.Finding, len(n.items))
	copy(out, n.items)
	for i := range out {
		out[i].AssetID = asset.ID
		if out[i].Scanner == "" {
			out[i].Scanner = raw.Scanner
		}
		if out[i].Occurrences < 1 {
			out[i].Occurrences = 1
		}
		out[i].Fingerprint = findings.Fingerprint(asset.ID, out[i])
	}
	return out, n.pkgs, nil
}

// recordPublisher keeps the events one scan publishes.
type recordPublisher struct {
	mu     sync.Mutex
	events []jobs.Event
}

func (p *recordPublisher) Publish(ev jobs.Event) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
}

func (p *recordPublisher) snapshot() []jobs.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.events)
}

// pathSource builds the fake source map used by most tests.
func pathSource() (*fakeSource, map[sources.TargetKind]sources.Source) {
	src := &fakeSource{kind: sources.KindPath}
	return src, map[sources.TargetKind]sources.Source{sources.KindPath: src}
}

// contains is strings.Contains with the argument order used for error checks.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// scannerRunStatuses reads the persisted scanner_runs of one scan.
func scannerRunStatuses(t *testing.T, db *sql.DB, scanID int64) map[string]string {
	t.Helper()

	rows, err := db.QueryContext(context.Background(), `SELECT scanner, status FROM scanner_runs WHERE scan_id = ?`, scanID)
	if err != nil {
		t.Fatalf("list scanner runs: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("close scanner runs: %v", err)
		}
	}()

	statuses := make(map[string]string)
	for rows.Next() {
		var scanner, status string
		if err := rows.Scan(&scanner, &status); err != nil {
			t.Fatalf("scan scanner run: %v", err)
		}
		statuses[scanner] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate scanner runs: %v", err)
	}
	return statuses
}
