---
id: BST-002
title: CI: GitHub Actions running make check on push/PR, build matrix smoke
phase: P0
status: done
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
- [x] `.github/workflows/ci.yml` runs `make check` on ubuntu for push/PR
- [x] Build smoke for darwin/linux/windows × amd64/arm64 (cross-compile only)
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
- 2026-11-11: .github/workflows/ci.yml (make check on ubuntu; cross-build matrix darwin/linux/windows × amd64/arm64, CGO_ENABLED=0). Actions pinned to latest majors (checkout v7.0.1, setup-go v7.0.0 per GitHub API). Verified locally: linux/windows × amd64/arm64 cross-builds OK; darwin/arm64 is the host build. Workflow not yet run on GitHub (needs push). Note: make check takes ~40 s due to Trivy lint.
