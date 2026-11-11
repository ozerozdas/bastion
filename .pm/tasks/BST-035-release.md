---
id: BST-035
title: Release pipeline: GoReleaser, install.sh, Homebrew tap
phase: P1
status: todo
owner_role: coder
depends_on: [BST-033]
estimate: M
---

## Context
E9. Human creates the tap repo and pushes the tag (§11.3.7).

## Scope
- In: `.goreleaser.yaml` (CGO off, 6 targets, checksums, SBOM optional), release workflow on tag, `install.sh` verifying checksums, Homebrew formula config.
- Out: signing/notarization (backlog).

## Acceptance criteria
- [ ] `goreleaser release --snapshot --clean` succeeds locally

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
