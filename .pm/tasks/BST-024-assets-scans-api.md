---
id: BST-024
title: Assets, scans and finding-state API
phase: P1
status: todo
owner_role: coder
depends_on: [017, 020, 022]
estimate: M
---

## Context
§6. Spec-first.

## Scope
- In: `GET/POST/DELETE /api/assets`; `POST /api/scans {asset_ids[]}`; `GET /api/scans?asset_id=&limit=`; `GET /api/scans/{id}`; `POST /api/scans/{id}/cancel`; `GET /api/scans/{id}/findings?type=&severity=&status=`; `POST /api/findings/{fingerprint}/state {asset_id, state, reason}`. Adding a repo asset resolves default branch via GitHub.
- Out: diff (P2).

## Acceptance criteria
- [ ] problem+json errors with human-readable hints (§7)
- [ ] Handler tests with fakes; TS types regenerated; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
