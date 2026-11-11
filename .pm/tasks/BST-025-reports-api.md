---
id: BST-025
title: Dashboard + latest findings API (internal/reports)
phase: P1
status: todo
owner_role: coder
depends_on: [017]
estimate: M
---

## Context
§6 /api/reports/dashboard, /api/findings; §7 Dashboard.

## Scope
- In: open findings totals by severity and by type (latest succeeded scan per asset, ignored excluded), top 5 riskiest assets (critical×1000 + high×100 + medium×10 + low), trend of open critical+high over the last 10 scans per asset, last scan time per asset. `GET /api/findings?asset_id=&severity=&type=`.
- Out: fix grouping (P3).

## Acceptance criteria
- [ ] Aggregations tested on a seeded temp DB
- [ ] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
