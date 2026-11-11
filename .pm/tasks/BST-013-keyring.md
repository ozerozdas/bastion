---
id: BST-013
title: Keyring wrapper with interface + in-memory fake
phase: P0
status: done
owner_role: coder
depends_on: [BST-005]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Keyring wrapper with interface + in-memory fake
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Interface + go-keyring impl + fake; env fallback, never plaintext file
- [x] Generates/stores the 32-byte HMAC `local_key` (§4.3)
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

```sh
make check
go test ./internal/secrets -v
CGO_ENABLED=0 go build ./...     # go-keyring is CGO-free (macOS: /usr/bin/security)
```

## Notes / Log

- Branch: `bst-013-keyring` (from `bst-005-app-paths`).
- `internal/secrets`:
  - `Store` interface (`Get`/`Set`/`Delete`) with `ErrNotFound` and
    `ErrReadOnly`.
  - `KeyringStore` (`zalando/go-keyring`, service `"bastion"`); maps
    `keyring.ErrNotFound` to our sentinel and wraps real keychain errors.
  - `MemoryStore` — exported fake so other packages' tests (connections, jobs)
    can use it without touching the keychain.
  - `EnvStore` — read-only fallback mapping `"github-token"` →
    `BASTION_GITHUB_TOKEN` (`EnvVarName`). Writes return `ErrReadOnly`.
  - `NewStore()` — production store: keyring first, then env on a miss or
    keyring failure. Writes/deletes go to the keyring only. No plaintext file
    anywhere.
  - `Probe(store)` / `Available()` — set/get/delete of a throwaway key
    (`bastion-availability-probe`), for `bastion doctor` (BST-012).
  - `LocalKey(store)` — get-or-create of the base64-encoded 32-byte HMAC key
    under `hmac-local-key`; invalid stored values are rejected. If the keyring
    cannot be read or written, falls back to `BASTION_HMAC_KEY` (base64, 32
    bytes); otherwise returns an error naming that variable and an
    `openssl rand -base64 32` hint. A package mutex makes the
    get-or-create atomic within the process.
- Dependencies added: `github.com/zalando/go-keyring v0.2.8` — required by §3
  for OS keychain storage; pure import surface, CGO-free on macOS (calls
  `/usr/bin/security`). `go mod tidy` also added `danieljoos/wincred` (windows
  backend) and bumped `godbus/dbus/v5` v5.1.0 → v5.2.2 (keyring v0.2.8
  requirement). Trivy build and tests are unaffected (`make check`).
- Unit tests use only `MemoryStore`/`failingStore`; `Available()` against the
  real keychain is not exercised automatically, so tests never prompt.
- Verified: `make check` → 0 lint issues, all tests pass; `CGO_ENABLED=0
  go build ./...` OK.
- 2026-11-11 review (orchestrator + reviewer): fixed review findings (HMAC env name unified to BASTION_HMAC_KEY with env-wins + read-back; gitleaks config parsed once in init to remove viper race; rune-safe redaction; cobra traverse hooks; dead slog check removed). `go test -race` + `make check` green; spike-gitleaks e2e with env key: secret absent from stdout/stderr. Done.
