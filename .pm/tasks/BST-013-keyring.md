---
id: BST-013
title: Keyring wrapper with interface + in-memory fake
phase: P0
status: todo
owner_role: coder
depends_on: [BST-005]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Keyring wrapper with interface + in-memory fake
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Interface + go-keyring impl + fake; env fallback, never plaintext file
- [ ] Generates/stores the 32-byte HMAC `local_key` (§4.3)
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
