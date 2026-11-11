---
id: BST-029
title: UI: Dashboard
phase: P1
status: todo
owner_role: coder
depends_on: [BST-025]
estimate: M
---

## Context
§7.1.

## Scope
- In: severity totals, findings by type, top 5 riskiest projects, critical+high trend (inline SVG, no chart lib), last scan per asset; empty state.

## Acceptance criteria
- [ ] No new npm dependency for charts
- [ ] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
