---
id: BST-015
title: "ADR-005: GitHub API + tarball network calls"
phase: P1
status: done
owner_role: architect
depends_on: []
estimate: S
---

## Context
§9.6: every new outbound call needs an ADR approved by the human.

## Scope
- In: ADR-005 listing endpoints, auth, redirect/logging rules, budgets, error hints.
- Out: implementation.

## Acceptance criteria
- [x] `.pm/decisions/ADR-005-github-network-calls.md` written
- [x] Özer approves (status → accepted)

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
