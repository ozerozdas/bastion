---
id: BST-026
title: "UI: Connections page (GitHub)"
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-020]
estimate: M
---

## Context
§7.2.

## Scope
- In: GitHub card: add (name + PAT in a password field, never re-shown), test, remove with confirm; status + login; empty state explains how to create a read-only PAT.
- Out: AWS/Docker cards (P2; show as "coming in v0.2").

## Acceptance criteria
- [ ] Errors show the API hint; PAT field cleared after submit
- [ ] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
