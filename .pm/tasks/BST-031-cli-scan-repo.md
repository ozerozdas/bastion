---
id: BST-031
title: "CLI: `scan --repo owner/name` and `--format json|table|sarif`"
phase: P1
status: todo
owner_role: coder
depends_on: [BST-018, BST-021]
estimate: M
---

## Context
§8 Phase 1, E7.

## Scope
- In: `--repo owner/name[@ref]` uses the GitHub source (token from keyring/env), persists like 018; `--format table` (severity-sorted, stdlib text/tabwriter), `--format sarif` (SARIF 2.1.0, stdlib JSON; rule per rule_id, result per finding, locations relative); `--fail-on <severity>` exit code 2 for CI.
- Out: SARIF upload (P4 GitHub Action).

## Acceptance criteria
- [ ] SARIF golden test `testdata/sarif/*` validates against the 2.1.0 schema shape (required fields)
- [ ] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
