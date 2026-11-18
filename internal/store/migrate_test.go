package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestScanScheduleMigrationDownUp proves the #58 migration's Down works on the
// bundled SQLite: ALTER TABLE ... DROP COLUMN can refuse a column named in a
// table CHECK, so the round trip is exercised rather than assumed.
func TestScanScheduleMigrationDownUp(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bastion.db")
	db, err := sql.Open(Driver, dataSourceName(path))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	provider, err := newProvider(db)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	// A row written before the down migration must survive it.
	asset, err := sqlcdb.New(db).CreateAsset(ctx, sqlcdb.CreateAssetParams{
		Kind:         "path",
		DisplayName:  "kept",
		Ref:          path,
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-18T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if asset.ScanSchedule != "off" {
		t.Fatalf("scan_schedule = %q, want off", asset.ScanSchedule)
	}

	if _, err := provider.DownTo(ctx, 9); err != nil {
		t.Fatalf("migrate down to 9: %v", err)
	}
	if columnExists(ctx, t, db, "assets", "scan_schedule") {
		t.Fatal("scan_schedule still present after Down")
	}
	var kept int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE id = ?`, asset.ID).Scan(&kept); err != nil {
		t.Fatalf("count asset row after Down: %v", err)
	}
	if kept != 1 {
		t.Fatalf("asset rows after Down = %d, want 1", kept)
	}

	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	if !columnExists(ctx, t, db, "assets", "scan_schedule") {
		t.Fatal("scan_schedule missing after re-Up")
	}
	reloaded, err := sqlcdb.New(db).GetAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("asset row after re-Up: %v", err)
	}
	if reloaded.ScanSchedule != "off" {
		t.Errorf("scan_schedule after re-Up = %q, want off", reloaded.ScanSchedule)
	}
}

// columnExists reports whether table has column.
func columnExists(ctx context.Context, t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("read columns of %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns of %s: %v", table, err)
	}
	return false
}
