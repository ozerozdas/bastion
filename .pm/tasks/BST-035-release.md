---
id: BST-035
title: "Release pipeline: GoReleaser, install.sh, Homebrew tap"
phase: P1
status: done
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
- [x] `goreleaser release --snapshot --clean` succeeds locally

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
- 2026-11-11: GoReleaser v2.20.1 pinned via `go run` (Makefile `release-snapshot`, release.yml); not a go.mod tool (large dep tree). `homebrew_casks` (brews deprecated since v2.10) to ozerozdas/homebrew-tap with xattr quarantine-removal post-install step (unsigned binary). `goreleaser check` ok; `make release-snapshot` ok in 3m33s: 6 archives + checksums.txt + cask; archive layout bastion/README.md/LICENSE matches install.sh; darwin_arm64 binary prints version. `sh -n install.sh` ok (shellcheck not installed). `make check` passes.
- Human steps: create repo ozerozdas/homebrew-tap; add repo secret HOMEBREW_TAP_GITHUB_TOKEN (fine-grained PAT, Contents: read/write on the tap repo only); push tag v0.1.0 (after BST-036).
