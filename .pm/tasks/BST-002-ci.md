---
id: BST-002
title: CI: GitHub Actions running make check on push/PR, build matrix smoke
phase: P0
status: ready
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: CI: GitHub Actions running make check on push/PR, build matrix smoke
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] `.github/workflows/ci.yml` runs `make check` on ubuntu for push/PR
- [ ] Build smoke for darwin/linux/windows × amd64/arm64 (cross-compile only)
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
