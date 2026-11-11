---
id: BST-016
title: "Store: persist a scan (scans, scanner_runs, packages, findings)"
phase: P1
status: review
owner_role: coder
depends_on: []
estimate: M
---

## Context
§5, E4. P0 only has CreateAsset/GetAsset/ListAssets/CreateScan. Jobs (022), CLI (018) and the API all need one persistence path.

## Scope
- In: sqlc queries + a `store` method that saves one finished scan in a single transaction: scan status/finish time/error/target_ref, scanner_runs, packages, findings (with `occurrences`), `first_seen_scan_id` = earliest scan of the same asset holding that fingerprint (else this scan). Queries to get/list scans (by asset, limit), get scan, list findings of a scan with type/severity filters, mark scan running/failed/canceled.
- In: asset helpers: get-or-create by (kind, ref), archive (soft delete).
- Out: finding_states (017), HTTP (024).

## Acceptance criteria
- [x] One transaction per persisted scan; failure leaves no partial rows
- [x] `first_seen_scan_id` correct across 3 consecutive scans (temp SQLite test)
- [x] Scan in `failed` state can still persist partial scanner_runs + findings
- [x] `make gen` regenerates sqlc code with no diff afterwards
- [x] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (branch `bst-016-scan-persistence`)

**Queries** (`db/queries/`):
- `assets.sql`: `GetOrCreateAsset` (`INSERT … ON CONFLICT (kind, ref) DO UPDATE`:
  refreshes `display_name`, fills `connection_id`/`default_branch` only when
  provided, never touches `id`/`created_at`/`metadata_json`/`archived_at`) and
  `ArchiveAsset` (sets `archived_at`, returns the row).
- `scans.sql`: `GetScan`, `MarkScanRunning` (sets `started_at` only when it is
  still NULL), `FinishScan` (status, `finished_at`, `error`, `target_ref`;
  an empty target ref keeps the stored one), `ListScansByAsset` (newest first,
  `ORDER BY id DESC LIMIT ?`), `InsertScannerRun`.
- `packages.sql` (new): `InsertPackage`.
- `findings.sql` (new): `InsertFinding`, `EarliestScanIDForFingerprint`
  (0 when the fingerprint is new), `ListFindingsByScan` with optional
  `type`/`severity` via `sqlc.narg(x) IS NULL OR col = sqlc.narg(x)`, ordered
  most severe first then fingerprint. Note: sqlc types the two `narg` filters as
  `interface{}` (sqlite engine); callers pass `nil` or the string value.

**Wrapper** (`internal/store/persist.go`):
`SaveScanResult(ctx, db *sql.DB, scanID int64, res ScanResult) error` builds one
transaction: `GetScan` (asset id is authoritative), `scanner_runs`, `packages`,
then per finding `EarliestScanIDForFingerprint` → fallback to this scan id →
`InsertFinding`, then `FinishScan`, then commit. Any error rolls back, so a
partial scan never lands. `ScanResult` reuses `findings.Package` /
`findings.Finding` and adds `ScannerRun` (scanner, versions, status, nil-able
duration, error, raw path) plus final `Status`/`TargetRef`/`Error`/`FinishedAt`
(UTC RFC3339, defaults to now). Input is checked before the transaction: final
status must be `succeeded|failed|canceled`, every finding needs a fingerprint.
Empty strings map to SQL NULL, `references` to `[]`, `occurrences < 1` to 1.

No schema change. Timestamps use `time.RFC3339` (UTC), matching the existing
store tests.

**Tests** (`internal/store/persist_test.go`, temp SQLite per test):
- 3 consecutive scans: fingerprint in all three keeps scan 1 as first seen, the
  one introduced in scan 2 keeps scan 2; asset id, occurrences and
  `references_json` verified.
- duplicate fingerprint in one scan (UNIQUE(scan_id, fingerprint)) → error, and
  zero scanner_runs/packages/findings rows; the scan is still `queued`.
- failed scan persists its partial runs (one succeeded, one failed with error),
  package, finding, error text and target_ref.
- `GetOrCreateAsset` idempotent (same id, refreshed name, original created_at),
  `ArchiveAsset` hides the asset from `ListAssets`.
- scan lifecycle: `MarkScanRunning` keeps the first `started_at`,
  `ListScansByAsset` newest-first with limit, `ListFindingsByScan` severity
  order and type/severity filters.

**Commands run**
- `go tool sqlc generate` → only the intended generated files changed;
  `make gen` afterwards left `git status` with no additional changes.
- `go test ./internal/store/ -run 'TestSaveScanResult|TestGetOrCreateAsset|TestScanLifecycle' -v` → all PASS.
- `make check` → fmt, lint, web-check, web-build, `go test ./...` and build all
  pass.
