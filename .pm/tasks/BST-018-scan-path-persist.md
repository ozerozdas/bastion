---
id: BST-018
title: "`scan --path` persists results under a real path asset"
phase: P1
status: todo
owner_role: coder
depends_on: [BST-016]
estimate: S
---

## Context
Backlog: CLI uses asset_id=0. Fingerprints must use the real asset id (§5).

## Scope
- In: resolve-or-create `path` asset (ref = absolute cleaned path), create scan with trigger `cli`, persist via 016, print JSON with real asset id + scan id. `--no-store` flag keeps the P0 stdout-only behaviour (used by golden-style CLI tests and CI).
- Out: `--repo` (031).

## Acceptance criteria
- [ ] Two scans of the same dir reuse one asset and produce identical fingerprints
- [ ] `--no-store` writes nothing to the DB
- [ ] Backlog line removed; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
