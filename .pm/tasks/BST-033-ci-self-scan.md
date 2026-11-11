---
id: BST-033
title: Self-scan in CI + `make gen` cleanup
phase: P1
status: review
owner_role: coder
depends_on: [BST-031]
estimate: S
---

## Context
P1 exit criterion; backlog items on testdata and make gen.

## Scope
- In: CI job runs `bastion scan --path . --no-store --format sarif --fail-on critical`, caches the Trivy DB; testdata excluded via a `--skip-dirs` flag (default none) or `.bastionignore`; remove the no-op `go generate` from `make gen`.

## Acceptance criteria
- [x] CI self-scan passes on master; backlog lines removed

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (bst-033-ci-self-scan; coder agent, finished by orchestrator)
- `bastion scan --skip-dirs <dir>` (repeatable, relative to the scan root; absolute/escaping rejected) → `scanners.Options.SkipDirs`. Trivy: resolved to absolute paths under the root (Trivy resolves `--skip-dirs` against the process CWD), doublestar globs kept. Gitleaks: anchored regex as a global allowlist, so skipped trees are never read.
- CI job `self-scan` (needs check): weekly-keyed Trivy DB cache, `make build`, `scan --path . --no-store --skip-dirs testdata --format sarif --fail-on critical`, SARIF uploaded as an artifact. Code-scanning upload deferred to P4.
- `make gen` already had no `go generate` line; both backlog lines removed.

Local self-scan (warm DB):
- without `--skip-dirs`: exit 2 (fixture criticals in testdata), 16 error / 19 warning / 5 note
- with `--skip-dirs testdata`: exit 0, 8 error / 15 warning / 4 note, 0 results under testdata. The 8 "error" results are GPL licences of go.mod `tool` dependencies (golangci-lint and its linters): dev tools, not shipped; informational.

Verification: `go test ./internal/scanners/... ./cmd/bastion/` ok; `make check` exit 0 (0 lint issues); ci.yml parses.
