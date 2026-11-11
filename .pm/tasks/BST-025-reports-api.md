---
id: BST-025
title: Dashboard + latest findings API (internal/reports)
phase: P1
status: review
owner_role: coder
depends_on: [BST-017]
estimate: M
---

## Context
§6 /api/reports/dashboard, /api/findings; §7 Dashboard.

## Scope
- In: open findings totals by severity and by type (latest succeeded scan per asset, ignored excluded), top 5 riskiest assets (critical×1000 + high×100 + medium×10 + low), trend of open critical+high over the last 10 scans per asset, last scan time per asset. `GET /api/findings?asset_id=&severity=&type=`.
- Out: fix grouping (P3).

## Acceptance criteria
- [x] Aggregations tested on a seeded temp DB
- [x] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

**Delivered**

- OpenAPI first: `GET /api/reports/dashboard` (totals_by_severity, totals_by_type,
  top_assets[≤5], trend[last 10 succeeded scans per asset], last_scans) and
  `GET /api/findings?asset_id=&severity=&type=&status=`. New component schemas
  (`Dashboard`, `SeverityTotals`, `TypeTotals`, `AssetRisk`, `AssetTrend`,
  `TrendScan`, `LastScan`, `Finding`, `FindingList`, `Severity`, `FindingType`,
  `FindingStatus`, `FindingState`, `AssetKind`, `ScanStatus`) and query
  parameters. `make gen` regenerates Go stubs and `web/src/api/schema.d.ts`.
- `db/queries/reports.sql`: `ReportTotalsBySeverity`, `ReportTotalsByType`,
  `ReportTopAssets`, `ReportTrendScans` (ROW_NUMBER window for the last 10
  succeeded scans per asset), `ReportLastScans`. SQL aggregates only — no full
  table load into Go.
- `internal/reports`: `Service.Dashboard` (aggregation + timestamp parsing) and
  `Service.Findings` (reuses the existing `ListLatestFindings` query, validates
  the enum filters and returns `ErrInvalid` for handlers to map to 400).
- `internal/httpapi/reports.go`: thin `ListFindings`/`GetDashboard` handlers
  mapping domain types to the generated shapes; wired via `httpapi.Config.Reports`
  and `cmd/bastion/serve.go`.

**Semantics (documented in the SQL and OpenAPI)**

- Every number counts open findings of each non-archived asset's latest
  *succeeded* scan; a newer failed/canceled/running scan does not shadow it.
- A `finding_states` decision hides the finding everywhere. Because decisions are
  keyed on (asset_id, fingerprint), ignores are applied **retroactively** to
  older trend points — the trend shows "open today", not "open then".
- Top assets: `score = critical*1000 + high*100 + medium*10 + low`; assets whose
  open findings are all `unknown` score 0 and are not ranked (`HAVING score > 0`).
- `last_scans` includes the newest scan whatever its status, so a failed last
  scan is visible.
- `GET /api/findings` validates `severity`/`type`/`status` (and a negative
  `asset_id`) in the service and answers problem+json 400.

**Tests**

- `internal/reports/reports_test.go`: seeded temp DB with two live assets and one
  archived asset, older + newer succeeded scans, a newer failed scan that
  persists findings, and an ignored finding. Asserts exact totals by severity
  (1/1/1/1/1) and type (vuln 3, secret 1, license 1), top assets (1101 and 10),
  trend (alpha 1→2, beta 0→0 showing the retroactive ignore), last scans, plus a
  12-scan case proving the trend keeps only the last 10, and findings mapping /
  `ErrInvalid` validation.
- `internal/httpapi/reports_test.go`: `/api/findings` without filters and with
  each filter (asset, severity, type, status, combination, unknown asset),
  effective status/state/reason in the response, and 400 problem+json for
  `severity=urgent`, `type=bogus`, `status=muted`, `asset_id=-1`;
  `/api/reports/dashboard` totals/top assets/trend/last scans through the real
  session-cookie stack.

**Implementation notes / caveats**

- sqlc v1.31.1 corrupted the generated SQL when `db/queries/reports.sql`
  contained a non-ASCII character in a comment (the query text was shifted by one
  byte at the boundary, producing `ORDER BY f.severi`). The query file is now
  ASCII-only; keep it that way, and re-check generated SQL after editing queries.
- No schema change, no new dependencies. `store`'s existing `ListLatestFindings`
  is reused rather than duplicated.

**Commands run (this worktree, branch `bst-025-reports-api`)**

- `go tool sqlc generate` — new `internal/store/sqlcdb/reports.sql.go`
- `go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml`
- `go vet ./internal/reports/ ./internal/httpapi/ ./cmd/...` — clean
- `go test ./internal/reports/... ./internal/httpapi/...` — ok
- `make gen` twice — second run produced no diff (checksums identical)
- `make check` — passed: fmt, golangci-lint, web typecheck, web build,
  `go test ./...` (all packages ok), `CGO_ENABLED=0 go build ... -o bin/bastion`
