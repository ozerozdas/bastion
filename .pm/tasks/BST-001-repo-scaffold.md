---
id: BST-001
title: Repo scaffold: layout §4.1, go.mod, Makefile, golangci-lint, .editorconfig, LICENSE
phase: P0
status: ready
owner_role: coder
depends_on: []
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Repo scaffold: layout §4.1, go.mod, Makefile, golangci-lint, .editorconfig, LICENSE
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Directories per §4.1 exist (only those with content; no empty placeholders)
- [ ] `go.mod` module `github.com/ozerozdas/bastion`, Go 1.26, dev tools as `tool` directives
- [ ] Makefile targets `build`, `check`, `gen`; `build` sets `CGO_ENABLED=0`
- [ ] `.golangci.yml`, `.editorconfig`, Apache-2.0 `LICENSE`, `.gitignore`
- [ ] `go run ./cmd/bastion version` prints a version
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
