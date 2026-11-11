---
id: BST-016
title: Store: persist a scan (scans, scanner_runs, packages, findings)
phase: P1
status: ready
owner_role: coder
depends_on: []
estimate: M
---

## Context
§5, E4. P0 only has CreateAsset/GetAsset/ListAssets/CreateScan. Jobs (022), CLI (018) and the API all need one persistence path.

## Scope
- In: sqlc queries + a `store` method that saves one finished scan in a single transaction: scan status/finish time/error/target_ref, scanner_runs, packages, findings (with `occurrences`), `first_seen_scan_id` = earliest scan of the same asset holding that fingerprint (else this scan). Queries to get/list scans (by asset, limit), get scan, list findings of a scan with type/severity filters, mark scan running/failed/canceled.
- In: asset helpers: get-or-create by (kind, ref), archive (soft delete).
- Out: finding_states (017), HTTP (024).

## Acceptance criteria
- [ ] One transaction per persisted scan; failure leaves no partial rows
- [ ] `first_seen_scan_id` correct across 3 consecutive scans (temp SQLite test)
- [ ] Scan in `failed` state can still persist partial scanner_runs + findings
- [ ] `make gen` regenerates sqlc code with no diff afterwards
- [ ] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
