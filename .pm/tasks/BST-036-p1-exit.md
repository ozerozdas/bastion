---
id: BST-036
title: Phase 1 exit check
phase: P1
status: done
owner_role: tester
depends_on: [all]
estimate: S
---

## Context
P1 exit criteria in phases/P1.md.

## Scope
- In: fresh machine run-through, timed; record in `phases/P1.md`; tag `v0.1.0` is done by the human.

## Acceptance criteria
- [x] First report in ≤5 minutes; results recorded

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
- 2026-11-12: first report in 22.0 s cold / 10.3 s warm; details and caveats in phases/P1.md. Install timing deferred to after v0.1.0.
