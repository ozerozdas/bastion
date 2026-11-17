package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store"
)

// stopTransport ends the MCP server right after it connects, so the command
// test does not need a client.
type stopTransport struct{}

func (stopTransport) Connect(context.Context) (mcp.Connection, error) {
	return nil, errors.New("stop before serving")
}

// TestMCPLeavesRunningScansUntouched proves `bastion mcp` is read-only: unlike
// serve's scan manager, it runs no recovery, so it must not fail the scans a
// concurrently running server owns (or that a crashed process left behind).
func TestMCPLeavesRunningScansUntouched(t *testing.T) {
	ctx := context.Background()
	paths := app.Paths{DataDir: t.TempDir()}

	db, err := store.Open(ctx, paths.DBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	asset, err := store.GetOrCreateAsset(ctx, db, findings.Asset{
		Kind:        findings.AssetKindPath,
		Ref:         paths.DataDir,
		DisplayName: "local project",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}
	scanID, err := store.StartScan(ctx, db, asset.ID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if err := store.MarkScanRunning(ctx, db, scanID); err != nil {
		t.Fatalf("MarkScanRunning: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seeded database: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := runMCP(cmd, paths, defaultServeDeps(), stopTransport{}); err == nil {
		t.Fatal("runMCP returned nil, want the transport's stop error")
	}

	db, err = store.Open(ctx, paths.DBPath())
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer func() { _ = db.Close() }()

	var status string
	if err := db.QueryRow("SELECT status FROM scans WHERE id = ?", scanID).Scan(&status); err != nil {
		t.Fatalf("read scan %d: %v", scanID, err)
	}
	if status != "running" {
		t.Fatalf("scan %d status = %q after bastion mcp, want running (no recovery)", scanID, status)
	}
}
