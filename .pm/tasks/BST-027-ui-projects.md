---
id: BST-027
title: "UI: Projects page, discover dialog, scan + live progress"
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-023, BST-024, BST-026]
estimate: L
---

## Context
§7.3.

## Scope
- In: assets table (last scan status, severity counts, Scan action), "Add projects" dialog (search + multi-select from discover), "Add local path" input, live status via SSE, cancel running scan, remove asset.
- Out: image assets (P2).

## Acceptance criteria
- [x] Empty state points to Connections or "Add local path"
- [x] Scan errors show human-readable cause + suggested fix
- [x] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
- `web/src/api/events.ts`: one `EventSource('/api/events')` per mounted Projects page; folds `scan.queued|progress|finished` into `Map<asset_id, {status, stage, scanner, error}>`; on `scan.finished` invalidates assets, scans, findings and dashboard; a reconnect (`open` after the first) drops stale live state and refetches assets because the server has no replay.
- `web/src/api/connections.ts`: added `discoverQuery(id)` (returns `DiscoveredRepo[]`, `already_added` comes from the server).
- Projects page: assets table with kind badge, ref + default branch, last-scan badge and relative time, live stage text (`running · trivy`), four open severity badges, row Scan/Cancel/View report/Remove (inline confirm), multi-select + "Scan selected".
- Failed scans: `AssetLastScan` carries no error, so a failed row reads `scansQuery(asset.id, 1)` for the error text; `suggestFix()` maps token/401, rate limit, not found/404 to a next step, default "See Scan History for details."
- Add projects panel is inline (no modal lib): connection select → discover with search + disabled `already added` rows, one create request per repo so errors stay per-repo, plus local-path form.
- No new npm dependencies. `make web-check` and `npm run build --prefix web` pass.

