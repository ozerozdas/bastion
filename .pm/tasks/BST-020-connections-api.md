---
id: BST-020
title: Connections service + API (GitHub)
phase: P1
status: review
owner_role: coder
depends_on: [BST-016, BST-019]
estimate: M
---

## Context
§6 connections endpoints, §7 Connections page. Spec-first: edit api/openapi.yaml, regenerate, then implement.

## Scope
- In: OpenAPI + handlers: `GET/POST /api/connections`, `POST /api/connections/{id}/test`, `DELETE /api/connections/{id}`, `GET /api/connections/{id}/discover`. Token stored in secrets store under `secret_ref` (`bastion.connection.<id>`); env fallback `BASTION_GITHUB_TOKEN`. Test updates `status`, `last_checked_at`, records the login in `config_json`. Delete removes the keyring entry.
- Out: AWS/Docker (P2).

## Acceptance criteria
- [x] Token never appears in any response, log line or DB column (test asserts)
- [x] `X-Bastion` required on POST/DELETE (existing middleware)
- [x] Discover lists repos with an `already_added` flag
- [x] Handler tests with fake GitHub + in-memory secrets; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (bst-020-connections-api)

**OpenAPI (spec-first).** `api/openapi.yaml` gained `GET/POST /api/connections`,
`POST /api/connections/{id}/test`, `DELETE /api/connections/{id}`,
`GET /api/connections/{id}/discover`, with `Connection` (id, kind, name,
status, login, hint, last_checked_at, created_at — never token or secret_ref),
`CreateConnectionRequest` (token `writeOnly`), `ConnectionList`,
`DiscoverReposResponse` and `DiscoveredRepo`. `make gen` regenerated Go and TS;
re-running it produces no diff.

**Queries.** `db/queries/connections.sql`: create (`ON CONFLICT (kind, name) DO
NOTHING`, so a duplicate is `sql.ErrNoRows` → 409), get, list, set secret_ref,
set status/last_checked_at/config_json, delete (`:execrows`), and
`ListRepoAssetRefs` for `already_added`. No schema change.

**Service.** `internal/connections/service.go` (+ `service_test.go`): `Create`
inserts the row, stores the token in the secrets store under
`bastion.connection.<id>`, records `secret_ref`, then tests once; a keyring
failure deletes the row again (tested). `Test` calls `User()`, writes
`status`/`last_checked_at` and login-or-hint into `config_json`. Token lookup is
keyring via `secret_ref`, then `BASTION_GITHUB_TOKEN` through
`secrets.EnvStore`. `Delete` removes the keyring entry then the row. `Discover`
calls `ListRepos` and marks existing repo asset refs. GitHub is behind the
injectable `GitHubFactory`; tests use a fake, no live calls.

**Handlers/wiring.** `internal/httpapi/connections.go` keeps handlers thin
(decode → service → problem+json). `httpapi.Config.Connections` is wired in
`cmd/bastion/serve.go`, which now opens SQLite at startup and constructs the
service; `serve_test.go` injects a temp DB and memory secret store.

**Accepted notes/risks (orchestrator-approved).**
- `Connection.hint` is an optional schema field beyond the literal task list;
  it carries the last failed test's ADR-005 hint so `status: error` is actionable
  without a token or GitHub response body.
- `already_added` uses every repo asset ref, not only this connection's:
  `assets` is unique on `(kind, ref)`, so a repo added by the CLI/another
  connection is already present for this one.
- The strict-handler request/response error hooks now emit problem+json for
  malformed bodies and write failures instead of text/plain; no existing
  endpoint changes behaviour otherwise.
- **Dependency exception (flagged for review):** path parameters make
  oapi-codegen emit `github.com/oapi-codegen/runtime`; `go.mod`/`go.sum` add
  that module (v1.9.0) plus its indirect `apapsch/go-jsonmerge/v2`. It is
  generated-code plumbing, not a chosen implementation library, and cannot be
  removed without changing `{id}` away from an integer path parameter.

**Tests.** `internal/httpapi/connections_test.go` covers create/list/test/delete
happy path, duplicate-name 409, 401 → `status error` + hint (create and test),
create with a bad token, discover `already_added`, discover 502 with hint, and
POST/DELETE without `X-Bastion` → 403 (nothing is created/deleted). Token
absence is asserted in every response body, in the captured slog output, and in
every TEXT column of every table (schema-discovered scan).

Verification:
- `go test ./cmd/... ./internal/httpapi/... ./internal/connections/...` → all ok.
- `make gen` twice → second run no diff (hash compare of generated files and diff).
- `make check` → pass: gofmt clean, golangci-lint 0 issues, `tsc --noEmit`,
  `vite build`, every `go test ./...` package ok, `go build -o bin/bastion`.
