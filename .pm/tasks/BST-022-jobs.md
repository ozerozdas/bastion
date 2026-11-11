---
id: BST-022
title: "Job system: queue, worker pool, cancel, lifecycle (internal/jobs)"
phase: P1
status: in_progress
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
- [ ] Tests with fake source/scanners: concurrency limit honoured, cancel → `canceled` + workspace cleaned, scanner error → `failed` with partial findings, recovery on restart
- [ ] `go test -race ./internal/jobs/...` passes
- [ ] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
