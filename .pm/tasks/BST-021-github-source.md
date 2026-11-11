---
id: BST-021
title: GitHub tarball source (internal/sources/github)
phase: P1
status: todo
owner_role: coder
depends_on: [BST-019]
estimate: M
---

## Context
§4.2 Source interface, ADR-005 budgets, §4.4 workspaces.

## Scope
- In: `Source` for `repo`: ref `owner/repo@sha` → download tarball → extract into `<cache>/workspaces/<random>` with the strip-top-dir GitHub layout → `Cleanup` removes it (unless keep-workspace). Safe extraction per ADR-005.
- Out: git history (P5).

## Acceptance criteria
- [ ] Tests with crafted tarballs: `../x`, absolute path, symlink escaping, hardlink, device file, oversize, too many files → all rejected or skipped with a reported reason
- [ ] Cancel mid-download removes the partial workspace
- [ ] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
