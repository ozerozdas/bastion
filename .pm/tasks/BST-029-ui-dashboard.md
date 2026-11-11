---
id: BST-029
title: "UI: Dashboard"
phase: P1
status: done
owner_role: coder
depends_on: [BST-025]
estimate: M
---

## Context
§7.1.

## Scope
- In: severity totals, findings by type, top 5 riskiest projects, critical+high trend (inline SVG, no chart lib), last scan per asset; empty state.

## Acceptance criteria
- [x] No new npm dependency for charts
- [x] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### Implemented
- `web/src/api/reports.ts`: typed `dashboardQuery` (`GET /api/reports/dashboard`) with exported
  `Dashboard`, `SeverityTotals`, `TypeTotals`, `AssetRisk`, `AssetTrend`, `LastScan` aliases.
- `web/src/pages/dashboard.tsx`:
  - Four severity tiles (critical/high/medium/low) plus an "unknown" tile only when non-zero.
    Numbers stay in foreground colour; severity colour is a small legend dot (§7).
  - Findings by type as proportional div bars, only non-zero types; license row is labelled
    `informational` because a license finding is not a security failure.
  - Top 5 riskiest projects table (score + per-severity count badges, zeros greyed out) linking
    to Security Reports.
  - Trend section: fixed-height inline SVG sparkline (96×24) per asset with `role="img"`,
    `<title>` and an aria-label listing the values oldest-first; no chart library.
  - Last scan per project table with status badge and relative finish time (title carries the
    absolute timestamp); unfinished scans show "not finished".
  - Empty state when `last_scans` is empty: explains "Connect GitHub or add a local path in
    Projects, then run a scan" with links to Connections and Projects.
  - Loading state and an error state that prints the RFC 9457 problem detail from `ApiError`.

### Decisions
- Removed the placeholder "Local API" health card from this page: the sidebar `HealthChip`
  already reports the same liveness, and §7.1 does not include it. `healthQuery` is untouched.
- `dashboardQuery` has no polling: the payload is a point-in-time aggregate, so a reload after a
  scan is the refresh path (consistent with other pages).
- Trend rows carry only `asset_id`; names are joined from `top_assets` and `last_scans`, with an
  `Asset <id>` fallback so a data gap never hides a series.

### Verified
- `make web-check` (tsc --noEmit) — pass.
- `npm run build --prefix web` — pass.
- `make check` — fmt, lint, web-check, web-build, `go test ./...`, `go build -o bin/bastion` — pass.
- No npm dependency added.
