// Package store owns bastion's SQLite database: it opens the file with the
// pragmas the rest of the application assumes and applies embedded goose
// migrations on startup (PROJECT_SPEC.md §3, §4.4).
//
// Generated query code lives in the sqlcdb subpackage; hand-written SQL is
// never used outside db/queries.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"

	schemadb "github.com/ozerozdas/bastion/db"
	// Register the pure-Go SQLite driver under the name "sqlite".
	_ "modernc.org/sqlite"
)

const (
	// Driver is the database/sql driver name registered by modernc.org/sqlite.
	// It is pure Go, so CGO_ENABLED=0 builds work (PROJECT_SPEC.md §3).
	Driver = "sqlite"
	// migrationsDir is the directory inside db.Migrations holding the SQL files.
	migrationsDir = "migrations"
	// busyTimeoutMillis is how long SQLite waits for a lock before returning
	// SQLITE_BUSY. Scanners write while the UI reads, so a short wait beats
	// surfacing "database is locked" to the user.
	busyTimeoutMillis = 5000
)

// Open opens the SQLite database at path, creating the parent directory and
// the file if needed, then applies all pending migrations. The returned
// *sql.DB is safe for concurrent use; callers own it and must close it.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("store: database path is required")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create database directory %s: %w", dir, err)
		}
	}

	database, err := sql.Open(Driver, dataSourceName(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// Fail here rather than on the first query: a misconfigured path or a
	// missing pragma should be a startup error.
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("store: connect %s: %w", path, err)
	}
	if err := Migrate(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

// Migrate applies every pending embedded migration. It is idempotent: a
// database already at the latest version is left untouched.
func Migrate(ctx context.Context, database *sql.DB) error {
	provider, err := newProvider(database)
	if err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("store: apply migrations: %w", err)
	}
	return nil
}

// MigrationVersion returns the schema version recorded by goose. Callers use
// it for diagnostics; it does not apply migrations itself.
func MigrationVersion(ctx context.Context, database *sql.DB) (int64, error) {
	provider, err := newProvider(database)
	if err != nil {
		return 0, err
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return version, nil
}

// newProvider builds a goose provider over the embedded migrations. goose is
// used as a library only; no CLI is required at runtime (PROJECT_SPEC.md §3).
func newProvider(database *sql.DB) (*goose.Provider, error) {
	if database == nil {
		return nil, errors.New("store: database is required")
	}
	migrations, err := fs.Sub(schemadb.Migrations, migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("store: open embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, database, migrations, goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return nil, fmt.Errorf("store: load migrations: %w", err)
	}
	return provider, nil
}

// dataSourceName builds the modernc.org/sqlite DSN with the pragmas every
// connection needs: WAL for concurrent readers, foreign key enforcement (off
// by default in SQLite), and a busy timeout so brief writer contention does
// not fail a request.
func dataSourceName(path string) string {
	query := url.Values{}
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMillis))

	return (&url.URL{Scheme: "file", Path: path, RawQuery: query.Encode()}).String()
}
