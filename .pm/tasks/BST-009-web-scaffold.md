---
id: BST-009
title: Web scaffold: Vite + React + TS + Tailwind + shadcn + TanStack; go:embed with SPA fallback
phase: P0
status: done
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
- [x] 5 nav items with placeholder pages
- [x] `web/dist` embedded; unknown paths fall back to index.html; `/api/*` never falls back
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
- 2026-11-11 (implementer + orchestrator): Vite 8 + React 19 + TS 7 (strict) + Tailwind 4 + TanStack Query/Router, shell per concept-design.html, 5 routes with next-step empty states, Dashboard shows /api/health. Deps (exact pins): react/react-dom 19.3.1 (UI), @tanstack/react-query 5.107.1 + react-router 1.170.46 (§3), clsx/tailwind-merge/class-variance-authority (shadcn component utilities), tailwindcss + @tailwindcss/vite 4.3.5, vite 8.3.8, @vitejs/plugin-react 6.3.0, typescript 7.0.2. Embed: web/embed.go `all:dist`; when dist lacks index.html the old placeholder page is served (fresh clone go test works); `make build` builds the UI first. Orchestrator fix: missing file-like paths (e.g. /favicon.svg) now 404 problem+json instead of SPA fallback (+test). CI: setup-node@v7 added. Verified: make check green (tsc, vite build, go lint/test/build); live smoke: / /projects /scan-history/x → 200 html; hashed js/css → 200 correct types; /api/nope → 404 problem+json; no cookie → 401; CSP default-src self; no inline script/style in dist. Screenshot: .pm/assets/bst-009-dashboard.png
