---
id: BST-005
title: internal/app paths + config (data dir, cache dir, flags, env)
phase: P0
status: todo
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: internal/app paths + config (data dir, cache dir, flags, env)
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Data/cache paths per §4.4, overridable by flags and `BASTION_*` env
- [ ] Unit tests for precedence flag > env > default
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
