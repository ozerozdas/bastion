package jobs_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestHandoffPollerRunsMCPQueuedScanOnce proves the server's poller claims a
// scan `bastion mcp` queued and runs it under the same scan id, exactly once.
func TestHandoffPollerRunsMCPQueuedScanOnce(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/handoff")
	src, sourceMap := pathSource()

	var calls atomic.Int32
	scanner := &fakeScanner{
		name:  "fake",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(context.Context, *sources.Workspace, scanners.Options) (*scanners.RawResult, error) {
			calls.Add(1)
			return rawResult("fake"), nil
		},
	}
	events := &recordPublisher{}
	manager := newManager(t, jobs.Config{
		DB:          db,
		Sources:     sourceMap,
		Scanners:    []scanners.Scanner{scanner},
		Normalizers: map[string]findings.Normalizer{"fake": &fakeNormalizer{}},
		Events:      events,
	})
	manager.StartHandoff()

	// The row appears after the first poll, so the ticker picks it up.
	scan, err := sqlcdb.New(db).CreateScan(context.Background(), sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: store.ScanTriggerAPI,
	})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	row := waitForStatus(t, db, scan.ID, store.ScanStatusSucceeded)
	if row.Trigger != store.ScanTriggerAPI {
		t.Errorf("trigger = %q, want %q", row.Trigger, store.ScanTriggerAPI)
	}
	if got := len(src.fetchedRefs()); got != 1 {
		t.Errorf("source fetched %d time(s), want 1", got)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("scanner ran %d time(s), want 1 (the same scan must not be queued twice)", got)
	}

	var count int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE asset_id = ?`, asset.ID).Scan(&count); err != nil {
		t.Fatalf("count scans: %v", err)
	}
	if count != 1 {
		t.Errorf("asset has %d scan rows, want 1 (the handoff reuses the queued row)", count)
	}

	var queuedEvent bool
	for _, event := range events.snapshot() {
		if event.Type == jobs.EventQueued && event.ScanID == scan.ID {
			queuedEvent = true
		}
	}
	if !queuedEvent {
		t.Error("no scan.queued event was published for the handed-off scan")
	}
}

// TestHandoffPollerPicksUpQueuedScanAfterRecover: Recover leaves a queued
// handoff scan (trigger api) alone, so one `bastion mcp` queued just before
// serve stopped survives the restart and the poller runs it exactly once. A
// running handoff scan is still failed: no worker survives the process.
func TestHandoffPollerPicksUpQueuedScanAfterRecover(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/handoff-recovered")
	_, sourceMap := pathSource()

	var calls atomic.Int32
	scanner := &fakeScanner{
		name:  "fake",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(context.Context, *sources.Workspace, scanners.Options) (*scanners.RawResult, error) {
			calls.Add(1)
			return rawResult("fake"), nil
		},
	}
	manager := newManager(t, jobs.Config{
		DB:          db,
		Sources:     sourceMap,
		Scanners:    []scanners.Scanner{scanner},
		Normalizers: map[string]findings.Normalizer{"fake": &fakeNormalizer{}},
	})
	queries := sqlcdb.New(db)
	ctx := context.Background()

	queued, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: store.ScanTriggerAPI,
	})
	if err != nil {
		t.Fatalf("CreateScan queued: %v", err)
	}
	running, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: asset.ID,
		Status:  "queued",
		Trigger: store.ScanTriggerAPI,
	})
	if err != nil {
		t.Fatalf("CreateScan running: %v", err)
	}
	if err := queries.MarkScanRunning(ctx, sqlcdb.MarkScanRunningParams{
		StartedAt: sql.NullString{String: "2026-11-17T10:00:00Z", Valid: true},
		ID:        running.ID,
	}); err != nil {
		t.Fatalf("MarkScanRunning: %v", err)
	}

	// Recover runs before the poller starts, exactly like serve.
	if err := manager.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	survivor, err := queries.GetScan(ctx, queued.ID)
	if err != nil {
		t.Fatalf("GetScan(%d): %v", queued.ID, err)
	}
	if survivor.Status != "queued" {
		t.Fatalf("queued handoff scan status = %q after Recover, want queued", survivor.Status)
	}
	dead, err := queries.GetScan(ctx, running.ID)
	if err != nil {
		t.Fatalf("GetScan(%d): %v", running.ID, err)
	}
	if dead.Status != store.ScanStatusFailed {
		t.Errorf("running handoff scan status = %q after Recover, want failed", dead.Status)
	}

	manager.StartHandoff()

	row := waitForStatus(t, db, queued.ID, store.ScanStatusSucceeded)
	if row.Trigger != store.ScanTriggerAPI {
		t.Errorf("trigger = %q, want %q", row.Trigger, store.ScanTriggerAPI)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("scanner ran %d time(s), want 1", got)
	}
}
