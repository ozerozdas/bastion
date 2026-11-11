---
id: BST-007
title: OpenAPI with /api/health; make gen runs oapi-codegen + openapi-typescript
phase: P0
status: ready
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: OpenAPI with /api/health; make gen runs oapi-codegen + openapi-typescript
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] `api/openapi.yaml` (3.1) with `/api/health`
- [ ] `make gen` regenerates Go server stubs and TS types; output committed
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
