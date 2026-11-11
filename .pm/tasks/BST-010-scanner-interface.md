---
id: BST-010
title: Scanner interface + findings model + fingerprint with unit tests
phase: P0
status: ready
owner_role: coder
depends_on: [BST-003, BST-004]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Scanner interface + findings model + fingerprint with unit tests
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Interfaces per §4.2; findings model per §5
- [ ] Fingerprint per §5 incl. image (path, not layer), secret (HMAC), misconfig rules; table tests
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
