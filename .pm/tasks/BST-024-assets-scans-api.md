---
id: BST-024
title: Assets, scans and finding-state API
phase: P1
status: done
owner_role: coder
depends_on: [BST-017, BST-020, BST-022]
estimate: M
---

## Context
§6. Spec-first.

## Scope
- In: `GET/POST/DELETE /api/assets`; `POST /api/scans {asset_ids[]}`; `GET /api/scans?asset_id=&limit=`; `GET /api/scans/{id}`; `POST /api/scans/{id}/cancel`; `GET /api/scans/{id}/findings?type=&severity=&status=`; `POST /api/findings/{fingerprint}/state {asset_id, state, reason}`. Adding a repo asset resolves default branch via GitHub.
- Out: diff (P2).

## Acceptance criteria
- [x] problem+json errors with human-readable hints (§7)
- [x] Handler tests with fakes; TS types regenerated; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### What
- `api/openapi.yaml` (spec first): `/api/assets` (GET list with `last_scan` + `open_counts`, POST create), `/api/assets/{id}` (DELETE = archive), `/api/scans` (GET newest first with `asset_id`/`limit`, POST queue), `/api/scans/{id}` (GET with `scanner_runs`), `/api/scans/{id}/cancel` (POST, 409 when not active), `/api/scans/{id}/findings` (GET with `type`/`severity`/`status`), `/api/findings/{fingerprint}/state` (POST set, DELETE clear). New schemas `Asset`, `AssetLastScan`, `AssetList`, `CreateAssetRequest`, `Scan`, `ScanList`, `ScannerRun`, `CreateScansRequest`, `ScanQueueResult`, `QueuedScan`, `SetFindingStateRequest`; existing `Severity`, `FindingType`, `FindingStatus`, `FindingState`, `AssetKind`, `ScanStatus`, `SeverityTotals`, `Finding`, `Problem` are reused.
- Queries: `GetAssetByKindRef`, `UnarchiveAsset`, `ListAssetSummaries` (newest scan + open severity counts scoped like the dashboard: newest **succeeded** scan, `finding_states` decisions hidden), `ListScans`.
- New package `internal/assets`: asset CRUD (repo default-branch resolution via an injected `RepoClientFactory` + `TokenSource`; path must be an existing absolute directory), scan list/read/cancel/enqueue (`trigger: ui`), finding-state set/clear (delegating to `store.SetFindingState`/`ClearFindingState`).
- `internal/reports.ScanFindings` / `ScanFilter` reuse `ListFindingsByScan` (effective status) and the existing `gen.Finding` mapping; `Filter.params` now shares `validateEnums`/`nullable`.
- `cmd/bastion/pipeline.go`: one manager builder (`newScanManager`) used by `bastion scan` and `bastion serve`; server resolver (`newRepoResolver`) resolves each repo asset's SHA with that asset's connection token (fallback `Service.Token`); `tokenDownloader` picks the token by repository asset for tarball fetches.
- `serve` wiring: one `jobs.Manager` for the server lifetime, `--concurrency` (default `jobs.DefaultConcurrency` = 2), `Recover` before serving, drain (`Shutdown`, 10 s) on stop. Missing HMAC key is a warning, not a startup failure.
- `internal/connections.Service.ConnectionToken(ctx, id)` exported (`id <= 0` → default `Token`).
- Tests (`internal/httpapi/assets_test.go`, fakes + temp DB, no network): assets create/list/archive/revive, validation problems (relative/missing path, bad repo ref, unknown kind, empty ref, GitHub failure → 502), queue → scan appears (`trigger: ui`, list omits `scanner_runs`, read includes it), all-or-nothing batch (unknown asset 404, empty 400, archived 409), cancel finished → 409 and unknown → 404, findings filters (`severity`, `type`, `status`), state set/clear with empty reason → 400, unknown asset 404, X-Bastion on all six mutations.

### Deviations / decisions
- **Clearing a decision is `DELETE /api/findings/{fingerprint}/state?asset_id=…`**, not `state: null`: the key is `(asset_id, fingerprint)` and both are needed. Documented in the spec operation.
- **`internal/assets` is one package for assets + scans + finding states** (the endpoints share one service and one store); scan *findings* stay in `internal/reports`, which already owned the read model and `gen.Finding` mapping.
- **`ConnectionToken`** was added to `connections.Service` rather than duplicating keyring lookup; repo asset creation uses an injected `TokenSource` (`Token` + `ConnectionToken`) so handlers/tests never touch the keyring.
- Archiving is a soft delete; re-adding the same `kind+ref` **revives the archived row** (same id), because fingerprints include the asset id. Revive keeps the stored branch; a later scan refreshes it through `GetOrCreateAsset`.
- `CreateScans` validates every id before queueing so a caller never receives a partial batch.
- Generated enum constant names changed (`gen.Path` → `gen.AssetKindPath`) because the new `CreateAssetRequestKind` enum adds `path`/`repo`; two assertions in `reports_test.go` were updated.
- serve resolves the HMAC key at startup (as the CLI does at scan time) but only logs a warning if it is unavailable.

### Commands + results
- `gofmt -w internal cmd` + `go build ./...` + `go vet ./...` → clean.
- `go test ./internal/httpapi -run 'TestAssets|TestQueueScan|TestCancel|TestScanFindings|TestMutationsRequireCSRF' -count=1` → `ok ... 0.350s`.
- `make gen` twice → exit 0 both times, `git status --porcelain` empty after each (no diff on rerun).
- `make check` → fmt, lint, web-check, web-build, `go test ./...` (all packages ok), `CGO_ENABLED=0 go build` all pass.

### Commits
- `6c30a51` wip(api): assets, scans and finding-state endpoints
- `878dcbc` feat(serve): run scans from the API through the shared pipeline
- `8327348` test(api): assets, scans and finding-state handlers
