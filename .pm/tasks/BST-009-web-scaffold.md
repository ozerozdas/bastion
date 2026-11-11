---
id: BST-009
title: Web scaffold: Vite + React + TS + Tailwind + shadcn + TanStack; go:embed with SPA fallback
phase: P0
status: todo
owner_role: coder
depends_on: [BST-008]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Web scaffold: Vite + React + TS + Tailwind + shadcn + TanStack; go:embed with SPA fallback
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] 5 nav items with placeholder pages
- [ ] `web/dist` embedded; unknown paths fall back to index.html; `/api/*` never falls back
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
