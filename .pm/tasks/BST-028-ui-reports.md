---
id: BST-028
title: "UI: Security Reports (findings table, drawer, ignore)"
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-024, BST-025]
estimate: L
---

## Context
§7.4.

## Scope
- In: per-asset findings table with type/severity/status filters, scanner + rule shown on every row, detail drawer (description, fixed version, references, occurrences, location), ignore/unignore with reason. License findings labelled informational.
- Out: fix plan tab (P3).

## Acceptance criteria
- [ ] Description and references rendered as plain text / safe links only (scanner output is untrusted, §4.3)
- [ ] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
