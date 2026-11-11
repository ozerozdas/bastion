---
id: BST-007
title: OpenAPI with /api/health; make gen runs oapi-codegen + openapi-typescript
phase: P0
status: review
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: OpenAPI with /api/health; make gen runs oapi-codegen + openapi-typescript
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] `api/openapi.yaml` (3.1) with `/api/health`
- [x] `make gen` regenerates Go server stubs and TS types; output committed
- [x] `make check` passes

### Detail
- [x] `/api/health` → `{status: "ok", version: string}` (`Health` schema)
- [x] Reusable RFC 9457 `Problem` schema + shared `#/components/responses/Problem`
      (`application/problem+json`), documented as the error shape for every `/api/*` call
- [x] `sessionCookie` apiKey/cookie security scheme (`bastion_session`), applied
      globally in the contract
- [x] Go codegen into `internal/httpapi/gen` (`std-http-server: true`, `strict-server: true`),
      config in `api/oapi-codegen.yaml`
- [x] TS types into `web/src/api/schema.d.ts` via `openapi-typescript` 7.13.0, no Vite/React (BST-009)
- [x] `make gen` is idempotent (verified by hashing both outputs across two runs)

## Verification
```
make gen && make gen && git status --short     # generated output -> no diff on the 2nd run
make check
head -20 internal/httpapi/gen/api.gen.go
head -5 web/src/api/schema.d.ts
```
Verified 2026-11-11: `make check` → `0 issues`, all tests ok, build ok (45 s).
`sha1sum -c` over `internal/httpapi/gen/api.gen.go` and `web/src/api/schema.d.ts`
unchanged across two consecutive `make gen` runs.

## Notes / Log

### Decisions
- **OpenAPI 3.1 is fully supported by oapi-codegen v2.8.2**, so no 3.0.3 downgrade
  was needed. Verified in the tool's own README (`Does oapi-codegen support
  OpenAPI 3.1?` → "Yes ... includes webhooks and version-aware handling of 3.1
  idioms such as `type: [T, "null"]` and enums via `oneOf` + `const`") and in
  `pkg/codegen/codegen.go`, which branches on `is31` for document parsing.
  `api/openapi.yaml` therefore uses `openapi: 3.1.0` with 3.1-only idioms
  (`const`, `examples` as arrays on scalar schemas).
- **Strict server + std-http server** combination generates
  `StrictServerInterface`, per-operation `XxxRequestObject`/`XxxResponseObject`
  and `HandlerWithOptions`; the handler in BST-008 returns typed responses, so a
  wrong status code cannot be emitted by accident.
- `Problem.additionalProperties: true` — RFC 9457 explicitly allows extension
  members, and the generated Go type then carries `AdditionalProperties` instead
  of silently dropping unknown fields.
- The shared `Problem` response documents `Content-Type: application/problem+json`
  as a header; oapi-codegen turns that into a `…ResponseHeaders` struct on the
  error response objects. They are unused today (the security middleware writes
  those responses before the strict handler runs) but exported, so harmless.
- Generated Go code is committed; `internal/store/sqlcdb` stays git-ignored as
  before (pre-existing repo convention, unchanged by this task).
- `api/openapi.yaml` keeps `info.version: 0.0.0` as a placeholder; the real
  version is injected at build time (`main.version`) and reported by
  `/api/health`, so the contract version does not need to track releases yet.

### Dependencies
- `github.com/oapi-codegen/oapi-codegen/v2` v2.8.2 (go.mod `tool`) — generates
  the std `net/http` server stubs from `api/openapi.yaml`, per §3.
- `openapi-typescript` 7.13.0 (web devDependency, exact pin) — generates the TS
  types the SPA (BST-009) compiles against.
