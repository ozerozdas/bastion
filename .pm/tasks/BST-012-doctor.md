---
id: BST-012
title: bastion doctor
phase: P0
status: todo
owner_role: coder
depends_on: [BST-005, BST-006]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: bastion doctor
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Prints paths, versions (bastion, Trivy, Gitleaks, DB), keyring availability, DB status
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
