---
id: BST-006
title: SQLite (modernc) + goose embedded migrations + sqlc; migration 0001 with all §5 tables
phase: P0
status: review
owner_role: coder
depends_on: [BST-005]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: SQLite (modernc) + goose embedded migrations + sqlc; migration 0001 with all §5 tables
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] WAL mode; migrations embedded and run on startup
- [x] Migration 0001 creates all §5 tables (including new finding types)
- [x] sqlc config + at least one query compiled; store test against temp SQLite file
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

```sh
make check
go test ./internal/store/... -v

# generated code is reproducible
make gen && git diff --exit-code -- internal/store/sqlcdb

# sqlc is pure Go, so CGO_ENABLED=0 works
CGO_ENABLED=0 go tool sqlc version
```

## Notes / Log

- Branch: `bst-006-sqlite-migrations` (from `master`).
- New package `internal/store`:
  - `Open(ctx, path) (*sql.DB, error)` creates the parent directory, opens the
    file through `modernc.org/sqlite` (driver name `sqlite`) and pings it before
    returning, so a bad path is a startup error.
  - DSN pragmas: `journal_mode(WAL)`, `foreign_keys(ON)` (SQLite defaults to
    off), `busy_timeout(5000)`.
  - `Migrate(ctx, db)` and `MigrationVersion(ctx, db)` wrap goose's
    `Provider` (library only, no CLI) over the embedded migrations. goose's
    logger is `NopLogger()` so library startup does not print.
- New package `db` (`db/embed.go`): `//go:embed migrations/*.sql` so the binary
  never needs `db/` on disk at runtime. Migration SQL stays in `db/migrations`
  per §4.1.
- `db/migrations/00001_init.sql`: goose `Up`/`Down`; all §5 tables
  (connections, assets, asset_links, scans, scanner_runs, packages, findings,
  finding_states) with:
  - CHECK enums: connection kind/status, asset kind, link source, scan
    status/trigger, scanner_run status, finding type (`vulnerability|secret|
    outdated|misconfig|license|malware|sast`) and severity, finding status,
    finding_states state; `packages.direct` is nullable 0/1.
  - FKs with `ON DELETE CASCADE` (assets/scans/findings) and `SET NULL` where
    history should survive (assets.connection_id, findings.first_seen_scan_id).
  - Indexes per §5: `findings(asset_id, fingerprint)`, `findings(scan_id)`,
    `scans(asset_id)`, `finding_states UNIQUE(asset_id, fingerprint)`; plus
    `assets(kind, ref) UNIQUE`, `assets(connection_id)`, `packages(scan_id)`,
    `findings(scan_id, fingerprint) UNIQUE`, `connections(kind, name) UNIQUE`.
  - Timestamps are `TEXT` RFC3339 UTC, defaulting to
    `strftime('%Y-%m-%dT%H:%M:%fZ','now')`; Go writes explicit values.
  - **secret_hmac**: the HMAC of a leaked secret lives inside
    `findings.location` (`file + rule_id + secret_hmac`, §5). There is no
    raw-secret column anywhere; `finding_states` keys on the fingerprint.
- sqlc: `sqlc.yaml` (engine sqlite, schema `db/migrations`, queries
  `db/queries`, out `internal/store/sqlcdb`), `sqlc-dev/sqlc v1.31.1` pinned as a
  `go.mod` tool. sqlc parses goose files and ignores the Down section. Queries:
  `CreateAsset`, `GetAsset`, `ListAssets`, `CreateScan` (all use `RETURNING *`;
  sqlite supports it). Generated code is committed.
- `make gen` now also runs `go tool sqlc generate` (cwd = repo root, so
  `sqlc.yaml` resolves without a `//go:generate` path dance).
- Tests (`internal/store/store_test.go`, temp SQLite file per test): migration
  creates exactly the 8 tables + version 1, WAL and foreign_keys are on,
  re-open is idempotent, asset create/get/list round-trip, scan create,
  CHECK rejects bad enum values, FK rejects a scan for a missing asset.
- Dependencies added (one-line justification each):
  - `modernc.org/sqlite` — pure-Go SQLite driver required by §3 for
    `CGO_ENABLED=0` builds (it was already in the module graph via Trivy).
  - `github.com/pressly/goose/v3` — embedded migrations as a library, §3.
  - `github.com/sqlc-dev/sqlc` (tool) — generates typed queries from SQL, §3;
    builds pure Go, verified with `CGO_ENABLED=0 go tool sqlc version` (v1.31.1).
- `go get` bumped shared transitive deps (otel v1.47.0, grpc v1.85.0, x/tools,
  modernc sqlite v1.62.0, …); `go mod tidy` added the missing
  `go.opentelemetry.io/otel/log` sum entry that lint's typecheck needed. Full
  `make check` (incl. Trivy/Gitleaks compile) is green after this.
- Binary size: 158,693,682 → 159,186,290 bytes (+492,608 B, +0.31%) with
  `make build` flags, measured against `master` at 6e2d19a.
- Verified: `make check` → 0 lint issues, all tests pass; `go test
  ./internal/store/... -v` → all store tests pass; `go tool sqlc generate` →
  exit 0 and reproducible output.

