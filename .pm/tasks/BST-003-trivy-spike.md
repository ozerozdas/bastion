---
id: BST-003
title: ADR-001 spike: Trivy as library (vuln + misconfig + license) on a local dir
phase: P0
status: todo
owner_role: coder
depends_on: [BST-001]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: ADR-001 spike: Trivy as library (vuln + misconfig + license) on a local dir
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Trivy pinned to an exact version; used only under `internal/scanners/trivy`
- [ ] Spike scans a local dir and prints JSON with vulns, misconfigs, licenses
- [ ] `decisions/ADR-001-trivy-as-library.md` records: Trivy version, binary size, clean build time, DB size, first-run time, CGO status
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
