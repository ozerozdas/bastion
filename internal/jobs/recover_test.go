package jobs_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestRecoverFailsUnfinishedScans proves startup recovery turns scans left
// queued or running by a previous process into failed ones.
func TestRecoverFailsUnfinishedScans(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/recover")
	queries := sqlcdb.New(db)
	ctx := context.Background()

	queued, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: "api",
	})
	if err != nil {
		t.Fatalf("CreateScan queued: %v", err)
	}
	running, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: "api",
	})
	if err != nil {
		t.Fatalf("CreateScan running: %v", err)
	}
	if err := queries.MarkScanRunning(ctx, sqlcdb.MarkScanRunningParams{
		StartedAt: sql.NullString{String: "2026-11-11T10:00:00Z", Valid: true},
		ID:        running.ID,
	}); err != nil {
		t.Fatalf("MarkScanRunning: %v", err)
	}
	succeeded, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: "api",
	})
	if err != nil {
		t.Fatalf("CreateScan succeeded: %v", err)
	}
	if err := queries.FinishScan(ctx, sqlcdb.FinishScanParams{
		Status:     store.ScanStatusSucceeded,
		FinishedAt: sql.NullString{String: "2026-11-11T10:01:00Z", Valid: true},
		ID:         succeeded.ID,
	}); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}

	m := newManager(t, jobs.Config{DB: db})
	if err := m.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	for _, id := range []int64{queued.ID, running.ID} {
		row, err := queries.GetScan(ctx, id)
		if err != nil {
			t.Fatalf("GetScan(%d): %v", id, err)
		}
		if row.Status != store.ScanStatusFailed {
			t.Errorf("scan %d status = %q, want failed", id, row.Status)
		}
		if !row.Error.Valid || row.Error.String != jobs.RecoveryError {
			t.Errorf("scan %d error = %q, want %q", id, row.Error.String, jobs.RecoveryError)
		}
		if !row.FinishedAt.Valid {
			t.Errorf("scan %d has no finished_at", id)
		}
	}

	row, err := queries.GetScan(ctx, succeeded.ID)
	if err != nil {
		t.Fatalf("GetScan(succeeded): %v", err)
	}
	if row.Status != store.ScanStatusSucceeded {
		t.Errorf("finished scan status = %q, want succeeded", row.Status)
	}

	// Recovery is idempotent: a second call leaves the rows as they are.
	if err := m.Recover(ctx); err != nil {
		t.Fatalf("second Recover: %v", err)
	}
}

// TestPublishesLifecycleEvents checks the event sequence wired for BST-023.
func TestPublishesLifecycleEvents(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/events")
	pub := &recordPublisher{}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     map[sources.TargetKind]sources.Source{sources.KindPath: &fakeSource{kind: sources.KindPath}},
		Scanners:    []scanners.Scanner{&fakeScanner{name: "fake", kinds: []sources.TargetKind{sources.KindPath}}},
		Normalizers: map[string]findings.Normalizer{"fake": &fakeNormalizer{}},
		Events:      pub,
		Concurrency: 1,
	})

	scanID, err := m.Enqueue(context.Background(), asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitForStatus(t, db, scanID, store.ScanStatusSucceeded)
	waitFor(t, "finished event", func() bool {
		for _, ev := range pub.snapshot() {
			if ev.Type == jobs.EventFinished && ev.ScanID == scanID {
				return true
			}
		}
		return false
	})

	events := pub.snapshot()
	var sawQueued, sawFetch, sawScan, sawFinished bool
	for _, ev := range events {
		if ev.ScanID != scanID || ev.AssetID != asset.ID {
			t.Errorf("event %+v does not name scan %d of asset %d", ev, scanID, asset.ID)
		}
		switch {
		case ev.Type == jobs.EventQueued && ev.Status == "queued":
			sawQueued = true
		case ev.Type == jobs.EventProgress && ev.Stage == jobs.StageFetch:
			sawFetch = true
		case ev.Type == jobs.EventProgress && ev.Stage == jobs.StageScan && ev.Scanner == "fake":
			sawScan = true
		case ev.Type == jobs.EventFinished && ev.Status == store.ScanStatusSucceeded:
			sawFinished = true
		}
	}
	if !sawQueued || !sawFetch || !sawScan || !sawFinished {
		t.Errorf("events = %+v, want queued, fetch progress, scan progress and finished", events)
	}
}
