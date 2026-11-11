---
id: BST-003
title: ADR-001 spike: Trivy as library (vuln + misconfig + license) on a local dir
phase: P0
status: review
owner_role: coder
depends_on: [BST-001]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: ADR-001 spike: Trivy as library (vuln + misconfig + license) on a local dir
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Trivy pinned to an exact version; used only under `internal/scanners/trivy`
- [x] Spike scans a local dir and prints JSON with vulns, misconfigs, licenses
- [x] `decisions/ADR-001-trivy-as-library.md` records: Trivy version, binary size, clean build time, DB size, first-run time, CGO status
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log

### 2026-11-11 — spike complete (coder)

**Result:** Trivy imports cleanly as a library, `CGO_ENABLED=0`, no subprocess.
Pinned `github.com/aquasecurity/trivy v0.76.2` (latest stable tag, 2026-11-05).
Trivy v0.76.2 has **no `replace` directives**, so none were copied into our go.mod.

**Files**
- `internal/scanners/trivy/trivy.go` — `ScanFS(ctx, dir, cacheDir) (json.RawMessage, error)`
  via `pkg/commands/artifact.{NewRunner,ScanFilesystem,Filter,Report}`; scanners fixed to
  `vuln,misconfig,license`; cache dir required from the caller; `viper.Reset()` per run;
  package-level mutex because Trivy's config/DB state is process-global.
- `internal/scanners/trivy/trivy_test.go` — target validation + scanner-set assertions (no network).
- `cmd/bastion/spike_trivy.go` — hidden `bastion spike-trivy <dir> [--cache-dir]`, JSON to
  stdout, diagnostics to stderr (also re-installs `slog.Default()`; Trivy's `pkg/log` init
  replaces it with a buffering handler that would swallow bastion's logs).
- `cmd/bastion/main.go` — one line registering the hidden command.
- `testdata/trivy/fixture/` — `package-lock.json` (lodash 4.17.15, minimist 1.2.0, one
  synthetic GPL-3.0 package) + `Dockerfile` (root user, `FROM ubuntu:latest`).

**Deps added (one-line justification)**
- `github.com/aquasecurity/trivy v0.76.2` — the scanner engine itself (§3).
- `github.com/spf13/viper v1.21.0` (now direct) — Trivy reads every flag through the global
  Viper instance; we must `viper.Reset()` between scans.
- `github.com/OpenPeeDeeP/depguard/v2 v2.2.1 → v2.3.0` and
  `github.com/ghostiam/protogetter v1.0.1 → v1.0.2` (indirect, lint-only) — Trivy forces
  `github.com/gobwas/glob v1.0.0`, and the older analyzer versions fail to compile
  (`undefined: glob.Glob`), which broke `make lint`.
- Go directive bumped `1.26.0 → 1.27.0` — required by Trivy v0.76.2; approved by Özer
  (spec §3 will say 1.27+).

**Measured (details and method in ADR-001)**
- binary 2.42 MiB → 147.9 MiB (155.1 MB decimal); exit gate is approximate, accepted.
- clean build (fresh GOCACHE) 1.97 s → 59.82 s (2.8 GB build cache); incremental ~1 s.
- cold scan 12.77 s, warm scan 0.46 s; vuln DB 1.6 GiB, checks bundle 2.6 MB, no Java DB.
- fixture findings: 8 vulnerabilities, 4 misconfigurations, 3 licenses.
- modules `go list -m all` 399 → 1163.

**Surprises / limitations**
- No build tags exist in Trivy to drop analyzers (grep of all non-test `//go:build` lines),
  so the §10 build-tag mitigation is unavailable; external-binary fallback stays on the shelf.
- Trivy's `pkg/log` `init()` hijacks `slog.Default()` with a buffering handler — `internal/app`
  (BST-005) must install bastion's logger at startup.
- Trivy's library state is process-global (Viper, DB handle, Java DB, slog): scans are
  serialized by a mutex here. The worker pool (BST-010/P1) must keep that or scan in
  separate processes.
- `Flags.AddFlags`/`Bind` skip the `Global` group, and the scan target comes from the
  positional arg — documented in ADR-001 as upgrade hazards.
- `Metadata.Version` is `null` in the report; use `trivy.Version` for
  `scanner_runs.scanner_version`.
- Machine note: the system volume was at 99 % (2.6 GiB free) and a `CGO_ENABLED=0` build
  died with `ENOSPC`; `GOCACHE` was moved to `/Volumes/Krypton/.cache/go-build` (now set via
  `go env -w`) and a cold build needs ≈2.8 GB of cache. Spike caches live under
  `/Volumes/Krypton/.cache/bastion-trivy-*`.

**Verification run**
```sh
make check     # gofmt clean, golangci-lint "0 issues.", go test ./... ok, CGO_ENABLED=0 build
./bin/bastion spike-trivy --cache-dir <cache> testdata/trivy/fixture | jq '.Results[].Class'
```
