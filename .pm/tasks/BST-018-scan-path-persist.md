---
id: BST-018
title: "`scan --path` persists results under a real path asset"
phase: P1
status: review
owner_role: coder
depends_on: [BST-016]
estimate: S
---

## Context
Backlog: CLI uses asset_id=0. Fingerprints must use the real asset id (§5).

## Scope
- In: resolve-or-create `path` asset (ref = absolute cleaned path), create scan with trigger `cli`, persist via 016, print JSON with real asset id + scan id. `--no-store` flag keeps the P0 stdout-only behaviour (used by golden-style CLI tests and CI).
- Out: `--repo` (031).

## Acceptance criteria
- [x] Two scans of the same dir reuse one asset and produce identical fingerprints
- [x] `--no-store` writes nothing to the DB
- [x] Backlog line removed; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (branch `bst-018-scan-path-persist`)

**`bastion scan` now persists by default** (`cmd/bastion/scan.go`):
- New `scanDeps` struct (doctor/serve style) injects the data/cache paths,
  `store.Open`/`Close`, `signal.NotifyContext`, the scanner list and the HMAC
  key lookup, so tests never touch the real keyring or data dir.
- Flow: resolve `--path` via `localpath` → `pathAsset` (ref = `filepath.Abs` +
  `Clean`, display name = base) → unless `--no-store`: open+migrate the DB at
  `paths.DBPath()`, `store.GetOrCreateAsset`, `store.StartScan` (queued,
  trigger `cli`), `store.MarkScanRunning` → `scanTarget` with the stored asset
  → `saveScan` → print JSON.
- `scanOutput` gains `scan_id,omitempty`; `asset.id` is the real row id. With
  `--no-store` neither key carries a value (asset id 0, no `scan_id`), so the P0
  document is unchanged and the DB file is never opened or created.
- Final state: succeeded, or failed with the scanner error and the partial
  results that were printed, or canceled when the context was canceled.
- Ctrl-C/SIGTERM cancel the scan context (the process no longer dies mid-scan)
  and the final write runs on a fresh 10 s context
  (`context.WithoutCancel` + timeout), so an interrupted scan is stored as
  `canceled`. A canceled scan returns `context.Canceled` (exit 1).
- A DB that cannot be opened fails the command before scanning: persistence is
  the default contract, so silently degrading to stdout-only would hide it.

**Store helpers** (`internal/store/persist.go`, thin wrappers over the existing
sqlc queries — no schema or query change):
- `GetOrCreateAsset(ctx, db, findings.Asset)` → asset with the real id;
- `StartScan(ctx, db, assetID, trigger)` → queued scan id (unexported
  `scanStatusQueued`);
- `MarkScanRunning(ctx, db, scanID)` records `started_at` once;
- `ScanTriggerCLI = "cli"`.

**Tests** (`cmd/bastion/scan_test.go`, real temp SQLite, fake scanners):
- `TestRunScanReusesOneAssetPerPath`: two scans of one dir → one asset row
  (abs cleaned ref, base display name), two `cli`/`succeeded` scans, identical
  fingerprints and `first_seen_scan_id` = first scan for the second scan's
  finding.
- `TestRunScanNoStoreWritesNoDatabase`: `openDB` is wired to fail the test; the
  data dir and DB file do not exist afterwards, output has asset id 0 and no
  `scan_id`.
- `TestRunScanCanceledIsPersisted`: scanner cancels the context mid-run → scan
  stored `canceled` with error `context canceled`; `runScan` returns an error
  matching `context.Canceled`.
- `fakeScanner` gained an optional `normalize` hook so fingerprints can use the
  scanned asset like real adapters do. Existing `scanTarget` tests unchanged.

**Commands run**
- `make check` → fmt (no diff), golangci-lint 0 issues, web typecheck, web
  build, `go test ./...` all ok, `CGO_ENABLED=0 go build -o bin/bastion` ok.
- `go test ./cmd/bastion -run 'TestRunScan|TestScanTarget' -v` → 5/5 PASS.
- Real binary smoke (temp data/cache, `BASTION_HMAC_KEY` set,
  `scan --path testdata/trivy/fixture` twice): asset id 1 both times, scan ids
  1 and 2, 13 findings with identical fingerprints, both runs `succeeded`/`cli`
  with `started_at`/`finished_at`; DB: 1 asset, findings `first_seen_scan_id=1`
  in both scans.
- Same command with `--no-store` on a fresh data dir → exit 0, asset id 0, no
  `scan_id` field, 13 findings, data dir/DB never created.
