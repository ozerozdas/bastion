package mcpserver_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/servelock"
)

// triggerScanResult is the structured output of trigger_scan, without an
// untrusted envelope: nothing in it comes from a scanned target.
type triggerScanResult struct {
	ScanID        int64  `json:"scan_id"`
	Status        string `json:"status"`
	AlreadyQueued bool   `json:"already_queued"`
}

func scanRowCount(t *testing.T, db *sql.DB, assetID int64) int {
	t.Helper()

	var count int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE asset_id = ?`, assetID).Scan(&count); err != nil {
		t.Fatalf("count scans of asset %d: %v", assetID, err)
	}
	return count
}

// TestTriggerScanRequiresRunningServe: with no serve holding the data
// directory's lock, the tool fails with the documented message and writes
// nothing at all.
func TestTriggerScanRequiresRunningServe(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/serve-down", "serve down")
	dir := t.TempDir()
	session := newSession(t, mcpserver.Config{
		Assets:       newAssetsService(t, db),
		Reports:      newReportsService(t, db),
		ServeRunning: func() bool { return servelock.Held(dir) },
	})

	text := callError(t, session, "trigger_scan", map[string]any{"asset_id": asset.ID})
	if !strings.Contains(text, "bastion serve is not running; start it to run scans") {
		t.Errorf("error = %q, want the not-running message", text)
	}
	if count := scanRowCount(t, db, asset.ID); count != 0 {
		t.Errorf("asset has %d scan row(s), want 0 (nothing may be queued without a serve)", count)
	}
}

// TestTriggerScanQueuesMCPRowForRunningServe holds the real serve lock, so the
// tool's check goes through servelock exactly like it does beside a live
// server. A second trigger returns the same scan instead of queueing a
// duplicate.
func TestTriggerScanQueuesMCPRowForRunningServe(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/serve-up", "serve up")
	dir := t.TempDir()
	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	session := newSession(t, mcpserver.Config{
		Assets:       newAssetsService(t, db),
		Reports:      newReportsService(t, db),
		ServeRunning: func() bool { return servelock.Held(dir) },
	})

	first := call[triggerScanResult](t, session, "trigger_scan", map[string]any{"asset_id": asset.ID})
	if first.ScanID <= 0 {
		t.Fatalf("scan_id = %d, want a positive id", first.ScanID)
	}
	if first.Status != "queued" {
		t.Errorf("status = %q, want queued", first.Status)
	}
	if first.AlreadyQueued {
		t.Error("already_queued = true on the first trigger")
	}

	var status, trigger string
	if err := db.QueryRowContext(context.Background(),
		`SELECT status, "trigger" FROM scans WHERE id = ?`, first.ScanID).Scan(&status, &trigger); err != nil {
		t.Fatalf("read queued scan: %v", err)
	}
	if status != "queued" || trigger != "api" {
		t.Errorf("scan = status %q trigger %q, want queued/api", status, trigger)
	}

	second := call[triggerScanResult](t, session, "trigger_scan", map[string]any{"asset_id": asset.ID})
	if second.ScanID != first.ScanID {
		t.Errorf("second scan_id = %d, want the already queued %d", second.ScanID, first.ScanID)
	}
	if !second.AlreadyQueued {
		t.Error("already_queued = false on a second trigger while the first scan is still queued")
	}
	if count := scanRowCount(t, db, asset.ID); count != 1 {
		t.Errorf("asset has %d scan row(s), want 1 (no duplicate)", count)
	}
}

// TestTriggerScanRejectsUnknownAndArchivedAssets: the tool validates the asset
// before writing, so a typo or a removed asset never leaves a queued scan.
func TestTriggerScanRejectsUnknownAndArchivedAssets(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()
	session := newSession(t, mcpserver.Config{
		Assets:       newAssetsService(t, db),
		Reports:      newReportsService(t, db),
		ServeRunning: func() bool { return servelock.Held(dir) },
	})

	t.Run("unknown asset", func(t *testing.T) {
		text := callError(t, session, "trigger_scan", map[string]any{"asset_id": 987654})
		if !strings.Contains(text, "not found") {
			t.Errorf("error = %q, want a not-found message", text)
		}
	})

	t.Run("archived asset", func(t *testing.T) {
		asset := seedAsset(t, db, findings.AssetKindRepo, "owner/archived", "archived")
		if _, err := db.ExecContext(context.Background(),
			`UPDATE assets SET archived_at = ? WHERE id = ?`,
			time.Now().UTC().Format(time.RFC3339), asset.ID); err != nil {
			t.Fatalf("archive asset: %v", err)
		}
		text := callError(t, session, "trigger_scan", map[string]any{"asset_id": asset.ID})
		if !strings.Contains(text, "archived") {
			t.Errorf("error = %q, want an archived message", text)
		}
		if count := scanRowCount(t, db, asset.ID); count != 0 {
			t.Errorf("archived asset has %d scan row(s), want 0", count)
		}
	})
}
