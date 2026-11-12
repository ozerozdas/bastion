# Architecture

The authoritative design document is [`PROJECT_SPEC.md`](../../PROJECT_SPEC.md); this page
is the short tour.

```
            ┌──────────────── bastion (single binary) ────────────────┐
 Browser ──▶│ HTTP server (127.0.0.1, token-guarded)                  │
 (React UI) │   ├── /api/*         OpenAPI handlers                   │
            │   ├── /api/events    SSE (scan progress)                │
            │   └── /*             embedded SPA                       │
            │                                                         │
            │ Services                                                │
            │   ├── connections   GitHub (token in keyring)           │
            │   ├── sources       fetch target → local workspace      │
            │   ├── jobs          worker pool, scan lifecycle         │
            │   ├── scanners      Scanner interface + adapters        │
            │   ├── findings      normalize, fingerprint, diff        │
            │   └── reports       dashboard aggregations              │
            │                                                         │
            │ Store: SQLite (sqlc)       Cache: vuln DBs, workspaces  │
            └─────────────────────────────────────────────────────────┘
```

## Life of a scan

1. **Queue** — UI (`POST /api/scans`) or CLI creates a scan; the job pool picks it up
   (default concurrency 2).
2. **Fetch** — a `Source` turns the target into a local workspace: a GitHub tarball of a
   resolved commit SHA, or a local directory.
3. **Scan** — each `Scanner` (Trivy, Gitleaks) runs in-process on the workspace.
4. **Normalize** — raw results become findings and packages, each with a fingerprint.
5. **Store** — saved to SQLite; previous ignore decisions apply by fingerprint.
6. **Report** — progress events go out over SSE; the workspace is deleted.

## Code map

| Path | What lives there |
|---|---|
| `cmd/bastion/` | Cobra commands: `serve`, `scan`, `doctor`, `version` |
| `internal/app/` | Wiring, config, paths |
| `internal/httpapi/` | Generated server, handlers, SSE, auth middleware |
| `internal/connections/` | GitHub connection management |
| `internal/secrets/` | Keyring wrapper (with an in-memory fake for tests) |
| `internal/sources/` | GitHub tarball and local path sources |
| `internal/scanners/` | `Scanner` interface; `trivy/` and `gitleaks/` adapters |
| `internal/findings/` | Model, normalization, fingerprint, diff |
| `internal/jobs/` | Queue, worker pool, lifecycle |
| `internal/reports/` | Dashboard aggregations |
| `internal/store/` | sqlc-generated queries + wrapper |
| `api/openapi.yaml` | API contract (Go and TS code generated from it) |
| `db/migrations/`, `db/queries/` | goose migrations, sqlc queries |
| `web/` | React + TypeScript + Vite UI, embedded via `go:embed` |
| `testdata/` | Golden files: raw scanner output → expected findings |

## Key rules

- **Scanner isolation** — only `internal/scanners/<name>/` may import that scanner's
  library. Trivy's internal API is unstable; this keeps upgrades contained.
- **Pure Go** — `CGO_ENABLED=0`; SQLite via `modernc.org/sqlite`.
- **Contract first** — API changes start in `api/openapi.yaml`, schema changes in a new
  migration.
- **Thin handlers** — logic lives in services.

## Tech stack

Go 1.27 · stdlib `net/http` · Cobra · `log/slog` · SQLite (modernc) · sqlc · goose ·
OpenAPI 3.1 (oapi-codegen, openapi-typescript) · Trivy · Gitleaks v8 · go-github ·
go-keyring · React · TanStack Query/Router · Tailwind + shadcn/ui · Recharts · GoReleaser.

Design decisions are recorded as ADRs in `.pm/decisions/`.
