---
id: BST-008
title: HTTP server with §4.3 security
phase: P0
status: ready
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
- [ ] Binds 127.0.0.1, random port unless `--port`
- [ ] Single-use token → HttpOnly SameSite=Strict cookie → 303 redirect without `t`
- [ ] Host header check, `X-Bastion: 1` on mutating requests, no CORS
- [ ] slog request logging with credential redaction; tests for each rule
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
