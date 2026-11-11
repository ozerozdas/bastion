---
id: BST-006
title: SQLite (modernc) + goose embedded migrations + sqlc; migration 0001 with all §5 tables
phase: P0
status: ready
owner_role: coder
depends_on: [BST-005]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: SQLite (modernc) + goose embedded migrations + sqlc; migration 0001 with all §5 tables
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] WAL mode; migrations embedded and run on startup
- [ ] Migration 0001 creates all §5 tables (including new finding types)
- [ ] sqlc config + at least one query compiled; store test against temp SQLite file
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
