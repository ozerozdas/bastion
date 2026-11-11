---
id: BST-004
title: Spike: Gitleaks library scan of a local dir with redaction
phase: P0
status: done
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Spike: Gitleaks library scan of a local dir with redaction
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Gitleaks v8 `detect` package used only under `internal/scanners/gitleaks`
- [x] Output never contains raw secrets: redacted (first 4 + `****`) + HMAC-SHA256 (§4.3)
- [x] Test proves a planted fake secret is detected and not present in output
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

```sh
make check
go test ./internal/scanners/gitleaks -v
go test ./internal/scanners/gitleaks -run TestScanDirDetectsAndRedacts -v

# import boundary
grep -rln 'gitleaks/v8' --include='*.go' . | grep -v '^./internal/scanners/gitleaks/'

# manual spike (uses the real keyring, creates `bastion`/`hmac-local-key`)
./bin/bastion spike-gitleaks <dir>
```

## Notes / Log

- Branch: `bst-004-gitleaks-spike` (from `bst-013-keyring`).
- `internal/scanners/gitleaks` (the only importer of Gitleaks):
  - `ScanDir(ctx, dir, key)` scans the working tree (no git history) through
    `sources.Files` + `Detector.DetectSource` with the embedded default config.
    Results are sorted by file, line, rule id for stable JSON.
  - `Finding{RuleID, File (relative, slash-separated), Line, Match, SecretHMAC}`.
    `Match` is `secret[:4] + "****"` (`"****"` for secrets ≤4 chars);
    `SecretHMAC` is hex HMAC-SHA256(key, secret). Gitleaks' raw `Secret`/`Match`
    fields never leave the package, so the API cannot leak them.
  - `spike-gitleaks <dir>` is a hidden command; it obtains the key from
    `secrets.LocalKey(secrets.NewStore())` and prints indented JSON.
- Dependencies added:
  - `github.com/zricethezav/gitleaks/v8 v8.30.1` — required by §3 (Gitleaks as
    a library). Note the repo moved to `github.com/gitleaks/gitleaks`, but the
    module still declares `module github.com/zricethezav/gitleaks/v8`; the
    declared path is the only importable one.
  - `github.com/rs/zerolog v1.33.0` — promoted to direct only to silence
    Gitleaks' package-level logger (`logging.Logger = zerolog.Nop()`); it was
    already in the module graph.
  - `github.com/charmbracelet/x/cellbuf` pinned to **v0.0.15** (was
    `v0.0.13-0.20250311...`): MVS selected Trivy's `x/ansi v0.11.8`, which is
    newer than the API the old cellbuf compiles against, so the graph did not
    build until cellbuf was bumped. Verified Trivy still builds/tests.
- Surprises / findings:
  - **Global state:** `detect.NewDetectorDefaultConfig()` parses through the
    process-global Viper instance, which Trivy also owns (ADR-001). Replaced
    with a local `viper.New()` over `config.DefaultConfig`; the only remaining
    global read is `viper.ConfigFileUsed()` inside `ViperConfig.Translate()` for
    a cosmetic `Path` field.
  - **Logging:** Gitleaks logs through a package-level zerolog logger that
    writes to stderr. It is silenced in this package's `init()` (which runs
    after Gitleaks' own init), so no scanned content can reach stdout/stderr.
  - **Default config:** 222 rules / 244 keywords. The AWS `aws-access-token`
    rule accepts `AKIA` + 16 chars from **`[A-Z2-7]`** (no 8/9/0/1); the first
    test fixture used 8/9 and silently matched nothing — corrected.
  - Test fixtures are generated in `t.TempDir()` and assembled by string
    concatenation, so no secret-shaped literal is committed.
- Binary size: before **155,069,090 B** (BST-013 tip, 155.1 MB) → after
  **158,693,682 B** (158.7 MB); delta **+3,624,592 B (+3.62 MB / +3.46 MiB)**.
  Gitleaks adds `go-re2` (wasm) and archive readers; no build tags were used.
- Verified: `make check` → 0 lint issues, all tests pass, `CGO_ENABLED=0`
  build OK. The command was not executed manually because it would write the
  HMAC key into the reviewer's real keychain; the adapter is covered by tests
  with the in-memory store pattern.
- 2026-11-11 review (orchestrator + reviewer): fixed review findings (HMAC env name unified to BASTION_HMAC_KEY with env-wins + read-back; gitleaks config parsed once in init to remove viper race; rune-safe redaction; cobra traverse hooks; dead slog check removed). `go test -race` + `make check` green; spike-gitleaks e2e with env key: secret absent from stdout/stderr. Done.
