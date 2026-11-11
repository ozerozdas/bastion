---
id: BST-014
title: Phase 0 exit check
phase: P0
status: ready
owner_role: coder
depends_on: [BST-001, BST-002, BST-003, BST-004, BST-005, BST-006, BST-007, BST-008, BST-009, BST-010, BST-011, BST-012, BST-013]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Phase 0 exit check
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Fresh clone → `make build` → run → browser opens → `bastion scan --path .` works
- [ ] Results recorded in `phases/P0.md`
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
