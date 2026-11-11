---
id: BST-017
title: finding_states: ignore by fingerprint, status on read, latest findings
phase: P1
status: todo
owner_role: coder
depends_on: [016]
estimate: M
---

## Context
§5 finding_states, §10 'false positives erode trust'. Decisions survive across scans because they key on (asset_id, fingerprint).

## Scope
- In: set/clear state (ignored|accepted_risk|false_positive) with required reason; finding `status` = `ignored` when a state exists, computed on read (do not rewrite old rows). Query: findings of the latest succeeded scan per asset, with filters (asset, type, severity, status).
- Out: bulk ignore, expiry (P3).

## Acceptance criteria
- [ ] Ignoring a fingerprint hides it in later scans of the same asset, not other assets
- [ ] Empty reason rejected
- [ ] Latest-scan query ignores failed/canceled scans
- [ ] Store tests on temp SQLite; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
