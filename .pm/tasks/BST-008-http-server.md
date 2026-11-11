---
id: BST-008
title: HTTP server with §4.3 security
phase: P0
status: done
owner_role: coder
depends_on: [BST-007]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: HTTP server with §4.3 security
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Binds 127.0.0.1, random port unless `--port`
- [x] Single-use token → HttpOnly SameSite=Strict cookie → 303 redirect without `t`
- [x] Host header check, `X-Bastion: 1` on mutating requests, no CORS
- [x] slog request logging with credential redaction; tests for each rule
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
- 2026-11-11 (orchestrator): finished after implementer step limit: registered `serve` subcommand (was missing), fixed 7 lint findings (errcheck on terminal writes, unused param, gosec G124 on loopback cookie with justification, G101 test token). Deps: github.com/pkg/browser (opens UI; was already transitive). `make check` green. Live smoke on random port: no cookie → 401 problem+json; bad Host → 421; ?t= → 303 to / with cookie; reused token → 401; cookie → 200 {"status":"ok"}; POST without X-Bastion → 403; OPTIONS with Origin → no Access-Control-* headers; listener 127.0.0.1 only; token absent from all log lines. Note: `/` also requires the session (stricter than §4.3, accepted: no unauthenticated surface).
