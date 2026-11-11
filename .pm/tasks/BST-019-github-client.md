---
id: BST-019
title: GitHub API client (internal/connections/github)
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-015]
estimate: M
---

## Context
ADR-005. Five endpoints, stdlib only.

## Scope
- In: client with injectable base URL + `http.Client`: `User`, `ListRepos` (Link pagination), `Repo`, `ResolveSHA`, `Tarball` (returns body reader, follows redirect, size cap). Error mapping with hints per ADR-005. Request URLs never logged.
- Out: storing tokens (020), extraction (021).

## Acceptance criteria
- [ ] httptest fake covers: pagination, 401, rate-limit 403, 404, redirect to another host drops `Authorization`
- [ ] No token or URL query string in any log line (test with a capturing slog handler)
- [ ] No new dependency; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
