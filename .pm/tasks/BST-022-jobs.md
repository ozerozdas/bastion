---
id: BST-022
title: "Job system: queue, worker pool, cancel, lifecycle (internal/jobs)"
phase: P1
status: review
owner_role: coder
depends_on: [BST-016, BST-021]
estimate: L
---

## Context
§4 jobs service, E3. Trivy runs must stay serialized (ADR-001), Gitleaks may run in parallel.

## Scope
- In: in-process queue; worker pool (default 2, `--concurrency`); pipeline fetch → scanners → normalize → merge → persist; per-scan context cancel; statuses queued → running → succeeded|failed|canceled; partial results persisted on scanner failure; startup recovery marks leftover queued/running scans failed ("bastion stopped during scan"); progress events published to a bus interface (consumed by 023).
- Out: scheduling (P5).

## Acceptance criteria
- [x] Tests with fake source/scanners: concurrency limit honoured, cancel → `canceled` + workspace cleaned, scanner error → `failed` with partial findings, recovery on restart
- [x] `go test -race ./internal/jobs/...` passes
- [x] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (bst-022-jobs; coder agent, finished by orchestrator)
- `internal/jobs`: `Manager` (Config: DB, Sources by kind, Scanners, Normalizers, Options func, Concurrency default 2, Events publisher, Resolve func). `Enqueue`, `Cancel` (`ErrScanNotActive` for unknown/finished), `Recover` (new sqlc `FailUnfinishedScans` → "bastion stopped during scan"), `Shutdown`/`Close`.
- Pipeline: mark running → resolve → fetch → scanners → normalize → merge → `SaveScanResult` (succeeded | failed with partial results | canceled). Workspace closed before persist; persist uses `context.WithoutCancel`. Events `scan.queued|scan.progress|scan.finished` (no-op default; SSE in BST-023).
- Serialization: optional `Serialized() bool` on scanners; `trivy.Scanner` returns true; per-scanner-name semaphore in the pool (ADR-001).
- `internal/store`: DSN adds `_txlock=immediate` (supported by modernc sqlite v1.62.0, sqlite.go:426). Concurrent `SaveScanResult` transactions otherwise hit SQLITE_BUSY on the read→write lock upgrade in WAL mode, which bypasses busy_timeout.
- Follow-up: `cmd/bastion/scan.go` `scanTarget`/`runScanner` duplicate this pipeline → unify in BST-031 (CLI runs through `jobs.Manager`).

Verification:
- `go test -race -count=2 ./internal/jobs/... ./internal/store/...` → ok
- `make check` → exit 0 (golangci-lint 0 issues, all tests, build)
- `make gen` → no further diff
