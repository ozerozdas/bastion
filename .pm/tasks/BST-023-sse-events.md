---
id: BST-023
title: SSE /api/events
phase: P1
status: todo
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
- [ ] Test: event published → received by a connected client; disconnect frees the subscriber
- [ ] Requires session cookie like every `/api/*`; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
