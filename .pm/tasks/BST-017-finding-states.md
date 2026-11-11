---
id: BST-017
title: "finding_states: ignore by fingerprint, status on read, latest findings"
phase: P1
status: review
owner_role: coder
depends_on: [BST-016]
estimate: M
---

## Context
§5 finding_states, §10 'false positives erode trust'. Decisions survive across scans because they key on (asset_id, fingerprint).

## Scope
- In: set/clear state (ignored|accepted_risk|false_positive) with required reason; finding `status` = `ignored` when a state exists, computed on read (do not rewrite old rows). Query: findings of the latest succeeded scan per asset, with filters (asset, type, severity, status).
- Out: bulk ignore, expiry (P3).

## Acceptance criteria
- [x] Ignoring a fingerprint hides it in later scans of the same asset, not other assets
- [x] Empty reason rejected
- [x] Latest-scan query ignores failed/canceled scans
- [x] Store tests on temp SQLite; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

Store layer only; no HTTP/CLI surface (BST-024/025/028 consume these).

**Queries**
- `db/queries/finding_states.sql` (new): `UpsertFindingState` (ON CONFLICT
  (asset_id, fingerprint) DO UPDATE replaces state + reason), `DeleteFindingState`,
  `GetFindingState`, `ListFindingStatesByAsset`.
- `db/queries/findings.sql`: `ListFindingsByScan` now LEFT JOINs `finding_states`
  and returns an effective `status` (`'ignored'` when a state row exists, else
  the stored status), plus `state` and `reason` for the UI, and accepts an
  optional `status` filter. New `ListLatestFindings`: findings of
  `MAX(scans.id)` with `status = 'succeeded'` per non-archived asset, with
  optional asset/type/severity/status filters and the same severity CASE order.
  Failed/canceled/running scans are skipped, so a failed newest scan does not
  hide the previous successful report.
- No schema change; `findings.status` rows are never rewritten. Any state
  (`ignored`, `accepted_risk`, `false_positive`) hides a finding; the state is
  what the UI shows as the reason.
- Effective status is `CAST(CASE ... AS TEXT)` so sqlc types it as `string`
  rather than `interface{}`; optional filters stay `interface{}` like BST-016.

**Go wrappers** (`internal/store/finding_state.go`)
- `SetFindingState(ctx, db, assetID, fingerprint, state, reason)` — rejects a
  nil DB, blank fingerprint, unknown state (naming the allowed values) and a
  blank/whitespace reason; the reason is trimmed before storage.
- `ClearFindingState(ctx, db, assetID, fingerprint)` — idempotent (deleting a
  missing state is not an error).
- Constants `FindingStateIgnored`, `FindingStateAcceptedRisk`,
  `FindingStateFalsePositive`. Everything else is used through `sqlcdb`.

**Tests** (`internal/store/finding_state_test.go`, temp SQLite via `openTestDB`)
- `TestFindingStateHidesOnlyItsOwnAsset`: ignore F on A → later scan of A reports
  `ignored` with state+reason, status filter works; asset B with the same
  fingerprint string stays `open` and has no state row; `ListLatestFindings`
  agrees for both.
- `TestSetFindingStateReplacesDecision`: re-deciding upserts one row and the
  effective status stays `ignored` while `state` becomes `false_positive`.
- `TestSetFindingStateValidatesInput`: empty/whitespace reason, unknown/empty
  state, blank fingerprint rejected with clear messages; nothing is stored.
- `TestListLatestFindingsUsesLatestSucceededScan`: newer failed and canceled
  scans are skipped, ordering is most-severe-first, asset/type/severity filters
  work.
- `TestClearFindingStateReopens`: clearing reopens the finding (status `open`,
  state/reason NULL), is idempotent and rejects a blank fingerprint.

**Quirk found**: sqlc's SQLite parser fails on `§` inside a `--` comment
(`no viable alternative ...`). SQL comments now avoid the section sign (Go
comments still use it).

**Commands run**
- `make gen` → no diff beyond the new/generated query files (API + web codegen
  unchanged); `git status` stable on a second run.
- `make check` → `golangci-lint: 0 issues`, `tsc --noEmit` clean, vite build ok,
  `go test ./...` ok, `CGO_ENABLED=0 go build -o bin/bastion ./cmd/bastion` ok.
- `go test ./internal/store -run 'TestFindingState|TestSetFindingState|TestListLatestFindings|TestClearFindingState' -v -count=1` → all PASS.

