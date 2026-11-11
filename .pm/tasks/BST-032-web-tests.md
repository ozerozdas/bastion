---
id: BST-032
title: "Frontend tests: Vitest logic + Playwright smoke for 5 pages"
phase: P1
status: todo
owner_role: tester
depends_on: [BST-026, BST-027, BST-028, BST-029, BST-030]
estimate: M
---

## Context
§9.5.

## Scope
- In: Vitest for non-trivial client logic; Playwright smoke that starts `bastion serve` against a seeded temp data dir, exchanges the token, and loads all 5 pages without console errors. Run in CI.

## Acceptance criteria
- [ ] Dependency justification in log (vitest, @playwright/test)
- [ ] CI job green

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
