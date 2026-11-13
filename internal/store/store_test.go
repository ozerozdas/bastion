package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// openTestDB opens a fresh database in a temporary directory. Every test uses
// its own file so nothing touches the user's real bastion.db.
func openTestDB(t *testing.T) (*sql.DB, string) {
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
	return db, path
}

func TestOpenRunsMigrations(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	want := []string{
		"asset_links",
		"assets",
		"connections",
		"finding_states",
		"findings",
		"packages",
		"scanner_runs",
		"scans",
	}
	var got []string
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'goose_db_version' ORDER BY name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("close table rows: %v", err)
		}
	}()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}

	version, err := store.MigrationVersion(ctx, db)
	if err != nil {
		t.Fatalf("MigrationVersion: %v", err)
	}
	if version != 2 {
		t.Fatalf("schema version = %d, want 2", version)
	}
}

func TestOpenEnablesWAL(t *testing.T) {
	db, _ := openTestDB(t)

	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}

	var foreignKeys int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db, path := openTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatalf("close first handle: %v", err)
	}
	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("re-open migrated database: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened database: %v", err)
		}
	}()

	version, err := store.MigrationVersion(ctx, reopened)
	if err != nil {
		t.Fatalf("MigrationVersion: %v", err)
	}
	if version != 2 {
		t.Fatalf("schema version after re-open = %d, want 2", version)
	}
}

func TestAssetRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	const createdAt = "2026-11-11T10:00:00Z"
	created, err := queries.CreateAsset(ctx, sqlcdb.CreateAssetParams{
		Kind:          "repo",
		DisplayName:   "bastion",
		Ref:           "ozerozdas/bastion",
		DefaultBranch: sql.NullString{String: "main", Valid: true},
		MetadataJSON:  `{"language":"go"}`,
		CreatedAt:     createdAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("CreateAsset returned id 0")
	}

	got, err := queries.GetAsset(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.Ref != created.Ref || got.Kind != "repo" || got.DisplayName != "bastion" {
		t.Fatalf("GetAsset = %+v, want the created asset", got)
	}
	if !got.DefaultBranch.Valid || got.DefaultBranch.String != "main" {
		t.Fatalf("default_branch = %+v, want main", got.DefaultBranch)
	}
	if got.CreatedAt != createdAt {
		t.Fatalf("created_at = %q, want %q", got.CreatedAt, createdAt)
	}

	assets, err := queries.ListAssets(ctx)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("ListAssets returned %d assets, want 1", len(assets))
	}
}

func TestCreateScan(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset, err := queries.CreateAsset(ctx, sqlcdb.CreateAssetParams{
		Kind:         "path",
		DisplayName:  "working tree",
		Ref:          "/tmp/project",
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-11T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	scan, err := queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID:   asset.ID,
		Status:    "queued",
		Trigger:   "cli",
		StartedAt: sql.NullString{String: "2026-11-11T10:01:00Z", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if scan.AssetID != asset.ID || scan.Status != "queued" || scan.Trigger != "cli" {
		t.Fatalf("CreateScan = %+v, want asset %d, queued, cli", scan, asset.ID)
	}
}

func TestEnumChecksRejectBadValues(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (kind, display_name, ref, created_at) VALUES ('bogus', 'x', 'x', '2026-11-11T10:00:00Z')`,
	); err == nil {
		t.Fatal("inserting assets.kind = 'bogus' succeeded, want CHECK constraint failure")
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO connections (kind, name, created_at) VALUES ('github', 'work', '2026-11-11T10:00:00Z')`,
	); err != nil {
		t.Fatalf("insert valid connection: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE connections SET status = 'maybe' WHERE name = 'work'`,
	); err == nil {
		t.Fatal("setting connections.status = 'maybe' succeeded, want CHECK constraint failure")
	}
}

func TestForeignKeyIsEnforced(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (asset_id, status, "trigger") VALUES (999, 'queued', 'cli')`,
	); err == nil {
		t.Fatal("inserting a scan for a missing asset succeeded, want foreign key failure")
	}
}
