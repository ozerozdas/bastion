---
id: BST-023
title: SSE /api/events
phase: P1
status: done
owner_role: coder
depends_on: [BST-022]
estimate: S
---

## Context
§6 events, §4.3 (cookie required).

## Scope
- In: `GET /api/events` streaming `scan.queued|scan.progress|scan.finished` JSON; heartbeat comment every 15 s; unsubscribe on disconnect; slow clients dropped, not blocking workers.
- Out: replay/Last-Event-ID.

## Acceptance criteria
- [x] Test: event published → received by a connected client; disconnect frees the subscriber
- [x] Requires session cookie like every `/api/*`; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
- `internal/events`: `Broker` implements `jobs.Publisher`. `Publish` never blocks:
  each subscriber has a 16-event buffered channel; a full one is closed and
  removed (slow subscriber dropped). `Subscribers()` exists for the disconnect test.
- `GET /api/events` is a hand-written handler (`internal/httpapi/events.go`)
  mounted on the same mux under the unchanged session/Host/security middleware.
  Frames are `event: <type>\ndata: <ScanEvent JSON>\n\n` with snake_case fields,
  `: ping` every 15 s, flush after every write, unsubscribes on `ctx.Done`.
- The operation is in `api/openapi.yaml` (documented, `ScanEvent` schema) but
  excluded from codegen via `output-options.exclude-operation-ids: [streamEvents]`:
  the strict generated server cannot flush per event. Models are still generated
  (`skip-prune`), and `make gen` reruns with no diff.
- Wiring: `serve` creates one `events.Broker`, passes it to the scan manager as
  `jobs.Config.Events` and to `httpapi.Config.Events`. A `Server` built without
  one gets its own silent broker, so the route and tests stay nil-safe.
- Tests: `internal/events` (delivery, idempotent unsubscribe, slow subscriber
  dropped without blocking Publish) and `internal/httpapi` (401 without cookie,
  three event types received through a real stream, disconnect returns
  subscriber count to 0).
- Verification: `make gen` idempotent (same diff hash on rerun), `make check`
  passed (fmt, golangci-lint, web typecheck, web build, go test ./..., build).
