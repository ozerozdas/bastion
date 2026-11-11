package jobs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestCancelRunning cancels a scan while its scanner is running: the final
// status is canceled and the workspace has been removed by the time it lands.
func TestCancelRunning(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/cancel-running")
	src, sourcesByKind := pathSource()

	started := make(chan struct{})
	sc := &fakeScanner{
		name:  "slow",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(ctx context.Context, _ *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     sourcesByKind,
		Scanners:    []scanners.Scanner{sc},
		Normalizers: map[string]findings.Normalizer{"slow": &fakeNormalizer{}},
		Concurrency: 1,
	})

	ctx := context.Background()
	scanID, err := m.Enqueue(ctx, asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner never started")
	}

	if err := m.Cancel(scanID); err != nil {
		t.Fatalf("Cancel(%d): %v", scanID, err)
	}
	row := waitForStatus(t, db, scanID, store.ScanStatusCanceled)
	if row.Error.Valid {
		t.Errorf("canceled scan error = %q, want empty", row.Error.String)
	}
	if got := src.cleanup.Load(); got != 1 {
		t.Errorf("workspace cleanups = %d, want 1", got)
	}

	if err := m.Cancel(999_999); !errors.Is(err, jobs.ErrScanNotActive) {
		t.Errorf("Cancel(unknown) = %v, want ErrScanNotActive", err)
	}
}

// TestCancelQueued cancels a scan that is waiting for a worker: it never
// fetches its target and is persisted as canceled immediately.
func TestCancelQueued(t *testing.T) {
	db := openTestDB(t)
	first := createAsset(t, db, "path", "first")
	second := createAsset(t, db, "path", "second")
	src, sourcesByKind := pathSource()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	sc := &fakeScanner{
		name:  "slow",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(ctx context.Context, ws *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
			if ws.Dir != "first" {
				return rawResult("slow"), nil
			}
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return rawResult("slow"), nil
		},
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     sourcesByKind,
		Scanners:    []scanners.Scanner{sc},
		Normalizers: map[string]findings.Normalizer{"slow": &fakeNormalizer{}},
		Concurrency: 1,
	})

	ctx := context.Background()
	firstID, err := m.Enqueue(ctx, first.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue first: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first scan never started")
	}

	secondID, err := m.Enqueue(ctx, second.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}
	if err := m.Cancel(secondID); err != nil {
		t.Fatalf("Cancel queued: %v", err)
	}
	// A queued cancel is final immediately: the worker never saw the job.
	waitForStatus(t, db, secondID, store.ScanStatusCanceled)
	if err := m.Cancel(secondID); !errors.Is(err, jobs.ErrScanNotActive) {
		t.Errorf("second Cancel = %v, want ErrScanNotActive", err)
	}

	close(release)
	waitForStatus(t, db, firstID, store.ScanStatusSucceeded)

	if got := src.fetchedRefs(); len(got) != 1 || got[0] != "first" {
		t.Errorf("fetched targets = %v, want only [first]", got)
	}
	if got := src.cleanup.Load(); got != 1 {
		t.Errorf("workspace cleanups = %d, want 1", got)
	}
}

// TestScannerErrorPersistsPartialResults proves one broken scanner fails the
// scan without hiding the findings another scanner produced.
func TestScannerErrorPersistsPartialResults(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/partial")

	good := &fakeScanner{name: "good", kinds: []sources.TargetKind{sources.KindPath}}
	bad := &fakeScanner{
		name:  "bad",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(context.Context, *sources.Workspace, scanners.Options) (*scanners.RawResult, error) {
			return nil, errors.New("boom")
		},
	}
	finding := findings.Finding{
		Type:     findings.TypeVulnerability,
		RuleID:   "CVE-2026-0001",
		Severity: findings.SeverityHigh,
		Title:    "example vulnerability",
		Location: "package.json",
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     map[sources.TargetKind]sources.Source{sources.KindPath: &fakeSource{kind: sources.KindPath}},
		Scanners:    []scanners.Scanner{good, bad},
		Normalizers: map[string]findings.Normalizer{"good": &fakeNormalizer{items: []findings.Finding{finding}}},
		Concurrency: 1,
	})

	scanID, err := m.Enqueue(context.Background(), asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	row := waitForStatus(t, db, scanID, store.ScanStatusFailed)
	if !row.Error.Valid || !contains(row.Error.String, "bad") {
		t.Errorf("scan error = %q, want it to name the failed scanner", row.Error.String)
	}

	rows, err := sqlcdb.New(db).ListFindingsByScan(context.Background(), sqlcdb.ListFindingsByScanParams{ScanID: scanID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 || rows[0].Scanner != "good" || rows[0].RuleID.String != "CVE-2026-0001" {
		t.Errorf("persisted findings = %+v, want the good scanner's finding", rows)
	}

	statuses := scannerRunStatuses(t, db, scanID)
	if statuses["good"] != "succeeded" || statuses["bad"] != "failed" {
		t.Errorf("scanner run statuses = %v, want good=succeeded bad=failed", statuses)
	}
}

// TestShutdownCancelsInFlight proves Shutdown stops accepting work, cancels a
// running scan and waits for its final state.
func TestShutdownCancelsInFlight(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/shutdown")
	src, sourcesByKind := pathSource()

	started := make(chan struct{})
	sc := &fakeScanner{
		name:  "slow",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(ctx context.Context, _ *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	m, err := jobs.New(jobs.Config{
		DB:          db,
		Sources:     sourcesByKind,
		Scanners:    []scanners.Scanner{sc},
		Normalizers: map[string]findings.Normalizer{"slow": &fakeNormalizer{}},
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	scanID, err := m.Enqueue(context.Background(), asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitForStatus(t, db, scanID, store.ScanStatusCanceled)
	if got := src.cleanup.Load(); got != 1 {
		t.Errorf("workspace cleanups = %d, want 1", got)
	}
	if _, err := m.Enqueue(context.Background(), asset.ID, "api"); !errors.Is(err, jobs.ErrShutdown) {
		t.Errorf("Enqueue after Shutdown = %v, want ErrShutdown", err)
	}
}
