---
id: BST-031
title: "CLI: `scan --repo owner/name` and `--format json|table|sarif`"
phase: P1
status: review
owner_role: coder
depends_on: [BST-018, BST-021]
estimate: M
---

## Context
§8 Phase 1, E7.

## Scope
- In: `--repo owner/name[@ref]` uses the GitHub source (token from keyring/env), persists like 018; `--format table` (severity-sorted, stdlib text/tabwriter), `--format sarif` (SARIF 2.1.0, stdlib JSON; rule per rule_id, result per finding, locations relative); `--fail-on <severity>` exit code 2 for CI.
- Out: SARIF upload (P4 GitHub Action).

## Acceptance criteria
- [x] SARIF golden test `testdata/sarif/*` validates against the 2.1.0 schema shape (required fields)
- [x] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (bst-031-cli-scan-repo; coder agent, finished by orchestrator)
- `scan --repo owner/name[@ref]`: token via `connections.Service.Token` (first GitHub connection's keyring entry, else `BASTION_GITHUB_TOKEN`); default branch via `Repo`, SHA via `ResolveSHA`; repo asset get-or-create (`store.GetOrCreateRepoAsset`). Exactly one of `--path`/`--repo`.
- Unified: stored scans (path and repo) run through `jobs.Manager` (concurrency 1) and wait for `scan.finished`; Ctrl-C → `Manager.Cancel`; output is loaded back from the DB (`store.LoadScanReport`). The direct `scanTarget` pipeline remains only for `--no-store` (no DB).
- `--format json|table|sarif`: JSON shape unchanged; table via text/tabwriter; SARIF 2.1.0 in `internal/report/sarif` with golden `internal/report/sarif/testdata/sarif/basic`.
- `--fail-on <severity>`: exit 2 when an open finding is at/above it; other errors exit 1.
- New sqlc queries `ListPackagesByScan`, `ListScannerRunsByScan`; `app.Paths.WorkspacesDir()`.
- Deviations: canceled scans store no error text (jobs contract); DB-loaded JSON lacks `match`/`secret_hmac` (not persisted per §5); golden lives next to the package instead of top-level `testdata/sarif`.

Verification:
- `go test -race -count=1 ./cmd/bastion ./internal/store ./internal/report/... ./internal/connections/...` → ok
- `make check` → exit 0 (golangci-lint 0 issues)
