---
id: BST-012
title: bastion doctor
phase: P0
status: done
owner_role: coder
depends_on: [BST-005, BST-006]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: bastion doctor
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Prints paths, versions (bastion, Trivy, Gitleaks, DB), keyring availability, DB status
- [x] `make check` passes

## Verification

```sh
make check
go test ./cmd/bastion -run 'TestRunDoctor|TestWriteDoctor' -v

# text and JSON reports against a throwaway data dir
./bin/bastion --data-dir /tmp/bastion-doctor --cache-dir /tmp/bastion-doctor-cache doctor
./bin/bastion --data-dir /tmp/bastion-doctor doctor --json

# HMAC key source switches to env; the value is never printed
BASTION_HMAC_KEY=$(openssl rand -base64 32) ./bin/bastion doctor

# hard failure only: unopenable database → exit 1
./bin/bastion --data-dir /dev/null/nope doctor; echo $?
```

## Notes / Log

- Branch: `bst-012-doctor` (from `bst-006-sqlite-migrations` tip).
- `cmd/bastion/doctor.go` (registered in the one-line `root.AddCommand` addition in
  `main.go`):
  - Prints: bastion version, Go version + OS/arch, data dir, cache dir, database
    path, DB status with goose schema version, Trivy and Gitleaks versions,
    keyring availability, HMAC key source.
  - `--json` prints the identical report as indented JSON; text is tab-aligned
    via `text/tabwriter`.
  - DB check calls `store.Open`, i.e. it creates the data dir and runs pending
    migrations, then `store.MigrationVersion` reports the goose version.
  - Hard failure only when the DB cannot be opened: the report is still printed
    and the command returns the error (cobra → exit 1). Keyring unavailable,
    unreadable schema version and close errors are warnings with exit 0.
  - Keyring availability uses the existing `secrets.Available()` probe. In
    production that writes and deletes a throwaway keychain entry (product
    behaviour, disclosed in `--help`); tests never call it.
  - HMAC key source checks `BASTION_HMAC_KEY` first, then reads
    `secrets.HMACKeyName` from the store. It never calls `LocalKey`, so doctor
    does not create a key, and it prints only the source ("env", "keyring",
    "missing"), never the value. Tests assert the value never appears in either
    output format.
  - Read-only for credentials: no token or secret is read or printed.
- Testability: all probes live in `doctorDeps` (function fields + a
  `secrets.Store`); `runDoctor`/`writeDoctorText`/`writeDoctorJSON` are tested
  with fakes. `cmd/bastion/doctor_test.go` covers healthy state, keyring
  unavailable (warning + exit 0), DB open failure (hard error), HMAC key from
  keyring and from env (no leak in text/JSON), text layout, JSON schema.
- Dependencies added: **none**.
- Binary size: 159,186,290 → 163,119,074 bytes (+3,932,784 B, +2.5%). Almost
  all of it is the pure-Go SQLite driver/goose runtime, which was not linked
  before because no command reachable from `main` imported `internal/store`
  yet; doctor is the first one. Total vs `master` (6e2d19a): +4,425,392 B
  (+2.8%).
- Verified: `make check` → 0 lint issues, all tests pass; `go test -count=1
  ./...` green; manual text + `--json` runs on a temp data dir (schema version
  1); `BASTION_HMAC_KEY=...` run reports `hmac key env` without the value;
  `/dev/null/nope` data dir reports `db status error` and exits 1.

- 2026-11-11 review (orchestrator + reviewer): review findings fixed on bst-010-review-fixes (length-prefixed fingerprint, per-scan merge with occurrences, license version key, Windows paths, deterministic CVSS, partial scanner results). make check green; fixture e2e 8 vuln/4 misconfig/1 license, both scanner runs succeeded. Done.
