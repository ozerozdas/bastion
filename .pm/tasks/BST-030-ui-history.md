---
id: BST-030
title: "UI: Scan History (list)"
phase: P1
status: done
owner_role: coder
depends_on: [BST-024]
estimate: S
---

## Context
§7.5 (list only in P1; diff in P2).

## Scope
- In: scans list (asset, status, trigger, duration, counts), filter by asset, link to report.

## Acceptance criteria
- [x] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
- Implemented `web/src/pages/history.tsx` only; no API or backend changes.
- Table is newest first (server order from `scansQuery`): project name from
  `assetsQuery` with `Asset <id>` fallback, status badge (queued/running/
  succeeded/failed/canceled), trigger label (UI/CLI/API), started as relative
  time with the full timestamp in `title`, duration as finished − started
  (`waiting` for queued, `running` while unfinished), and failed-scan error text
  truncated with the full message in `title`.
- Project filter is a labelled `<select>` (all projects + non-archived assets)
  driving `scansQuery(assetId)`.
- Each project name links to `/security-reports?asset=<id>`; the reports page
  consumes that search param in BST-020.
- `refetchInterval` polls every 5 s only while a listed scan is queued or
  running, then stops.
- Empty states: no scans at all shows "No scans yet — add a project and press
  Scan" with a link to /projects and the v0.2 comparison note; an empty filtered
  result explains how to scan that project. Load and error states mirror the
  dashboard.
- No new npm dependencies.
- Verified: `make web-check` (tsc --noEmit), `npm run build --prefix web`, and
  `make check` (fmt, lint, web-check, web-build, go test ./..., build) all pass.
