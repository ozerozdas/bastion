---
id: BST-034
title: "README: quickstart, threat model, network calls, demo GIF"
phase: P1
status: todo
owner_role: coder
depends_on: [BST-027, BST-028, BST-031]
estimate: M
---

## Context
§8 Phase 1, E8, §9.6.

## Scope
- In: what/why, install, 5-minute quickstart, CLI usage, "Network calls" (Trivy DB, GitHub per ADR-005; nothing else), threat model (localhost, token/cookie, Host check, CSRF header, secrets handling, untrusted content), demo GIF.

## Acceptance criteria
- [ ] Every outbound call in code is listed (grep for `http.` clients)

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
