---
id: BST-027
title: "UI: Projects page, discover dialog, scan + live progress"
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-023, BST-024, BST-026]
estimate: L
---

## Context
§7.3.

## Scope
- In: assets table (last scan status, severity counts, Scan action), "Add projects" dialog (search + multi-select from discover), "Add local path" input, live status via SSE, cancel running scan, remove asset.
- Out: image assets (P2).

## Acceptance criteria
- [ ] Empty state points to Connections or "Add local path"
- [ ] Scan errors show human-readable cause + suggested fix
- [ ] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
