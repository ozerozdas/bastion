---
id: BST-026
title: "UI: Connections page (GitHub)"
phase: P1
status: done
owner_role: coder
depends_on: [BST-020]
estimate: M
---

## Context
§7.2.

## Scope
- In: GitHub card: add (name + PAT in a password field, never re-shown), test, remove with confirm; status + login; empty state explains how to create a read-only PAT.
- Out: AWS/Docker cards (P2; show as "coming in v0.2").

## Acceptance criteria
- [x] Errors show the API hint; PAT field cleared after submit
- [x] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### Implementation
- `web/src/api/connections.ts` — typed query/mutation hooks (`connectionsQuery`,
  `useCreateConnection`, `useTestConnection`, `useDeleteConnection`), all using
  `web/src/api/client.ts`; every mutation invalidates `['connections']`.
- `web/src/pages/connections.tsx` — GitHub section: rows with name, status badge
  (ok / error / untested), login, last test time, hint on error, Test and an
  inline two-step Remove confirm (no modal). Add form: name + `type=password`
  PAT with `autocomplete=off`; token is cleared in `onSettled` (success *and*
  failure) and never rendered back. Empty state explains fine-grained
  (`Contents: read` + `Metadata: read`) vs classic (`repo` read) tokens, links
  to https://github.com/settings/personal-access-tokens/new, and states the
  token lives in the OS keychain. AWS and Docker are disabled cards badged
  "coming in v0.2".
- Error handling: `ApiError.message` already carries the problem+json `detail`,
  so list/test/remove failures show it with a suggested fix; a 409 on create is
  translated to "name already in use → pick a different name". A create whose
  immediate test fails (still HTTP 201) shows the returned `hint` as a warning
  instead of pretending the add failed.
- `web/src/api/client.ts` — added `remove()` (DELETE) and made the POST body
  optional, needed by `POST /api/connections/{id}/test`. `X-Bastion: 1` was
  already sent for every mutating method and still is; no other change.
- No new npm dependencies.

### Verification (all run in this worktree)
- `make web-check` → `tsc --noEmit`, no errors.
- `make check` → fmt, golangci-lint, web-check, web-build, `go test ./...`
  (all packages ok), `go build -o bin/bastion ./cmd/bastion` — pass.
- `npm run build --prefix web` → 172 modules, build ok.
- Smoke test against the real binary with a throwaway data dir:
  `./bin/bastion serve --no-browser --data-dir <tmp> --port 47913`, visited
  the printed token URL and opened Connections. Empty state, form, disabled
  AWS/Docker cards render; no console errors. No connection was created, so
  the OS keychain was not touched.

### Open points
- Inline Remove confirm is rendered in the row (no dialog), per scope.
- Login/hint come from the API only; the UI never sees or stores the token.
