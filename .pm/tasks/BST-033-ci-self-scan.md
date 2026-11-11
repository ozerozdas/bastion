---
id: BST-033
title: Self-scan in CI + `make gen` cleanup
phase: P1
status: todo
owner_role: coder
depends_on: [BST-031]
estimate: S
---

## Context
P1 exit criterion; backlog items on testdata and make gen.

## Scope
- In: CI job runs `bastion scan --path . --no-store --format sarif --fail-on critical`, caches the Trivy DB; testdata excluded via a `--skip-dirs` flag (default none) or `.bastionignore`; remove the no-op `go generate` from `make gen`.

## Acceptance criteria
- [ ] CI self-scan passes on master; backlog lines removed

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
