---
id: BST-011
title: bastion scan --path <dir> --format json via interface + normalizers (golden tests)
phase: P0
status: todo
owner_role: coder
depends_on: [BST-010]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: bastion scan --path <dir> --format json via interface + normalizers (golden tests)
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Golden tests `testdata/trivy/*`, `testdata/gitleaks/*`; `-update` flag
- [ ] `bastion scan --path . --format json` prints normalized findings from both scanners
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
