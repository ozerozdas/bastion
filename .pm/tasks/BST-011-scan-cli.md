---
id: BST-011
title: bastion scan --path <dir> --format json via interface + normalizers (golden tests)
phase: P0
status: review
owner_role: coder
depends_on: [BST-010]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: bastion scan --path <dir> --format json via interface + normalizers (golden tests)
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Golden tests `testdata/trivy/*`, `testdata/gitleaks/*`; `-update` flag
- [x] `bastion scan --path . --format json` prints normalized findings from both scanners
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log

## Notes / Log

### 2026-11-11 — implemented (bst-011-scan-cli)
- `bastion scan --path <dir> --format json` runs Trivy then Gitleaks serially through `scanners.Scanner` + `findings.Normalizer`, and prints `{asset, findings[], packages[], scanner_runs[]}`.
- Gitleaks key: `secrets.LocalKey(secrets.NewStore())` (so `BASTION_HMAC_KEY` wins); Trivy cache: `<cache-dir>/trivy` via `app.Paths.TrivyCacheDir()`.
- Removed the temporary `spike-trivy` and `spike-gitleaks` commands; `scan` supersedes both.
- Golden tests (with `-update`): `testdata/trivy/fixture/input.json` → `expected.json`, and `testdata/gitleaks/{aws-key,two-files}/input.json` → `expected.json`. The Trivy input is the saved warm report (no network needed); Gitleaks inputs use the redacted struct form only (no real-format secrets). Shared golden helper lives in `internal/testutil`.
- `-update` was used once to create the four expected files, then reviewed.

Verification:
- `make check` → golangci-lint 0 issues, all tests pass, build OK.
- `BASTION_HMAC_KEY=$(openssl rand -base64 32) ./bin/bastion --cache-dir <root whose trivy/ symlinks the warm cache> scan --path testdata/trivy/fixture --format json` → exit 0; 15 findings (8 vulnerability, 4 misconfig, 3 license), 3 packages, 2 scanner_runs (trivy 0.76.2, gitleaks 8.30.1); severities 1 critical / 7 high / 4 medium / 3 low.
- `... scan --path . --format json` → exit 0; 616 findings (10 vulnerability, 601 license, 4 misconfig, 1 secret), 576 packages, 2 scanner_runs (trivy ~3.0 s, gitleaks ~1.6 s). The single secret match is the pre-existing fake AWS key literal in `internal/scanners/gitleaks/gitleaks_test.go`; it is not part of this task's fixtures.
