---
id: BST-004
title: Spike: Gitleaks library scan of a local dir with redaction
phase: P0
status: ready
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Spike: Gitleaks library scan of a local dir with redaction
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [ ] Gitleaks v8 `detect` package used only under `internal/scanners/gitleaks`
- [ ] Output never contains raw secrets: redacted (first 4 + `****`) + HMAC-SHA256 (§4.3)
- [ ] Test proves a planted fake secret is detected and not present in output
- [ ] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log
