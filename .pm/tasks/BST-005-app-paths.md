---
id: BST-005
title: internal/app paths + config (data dir, cache dir, flags, env)
phase: P0
status: review
owner_role: coder
depends_on: [BST-001]
estimate: S
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: internal/app paths + config (data dir, cache dir, flags, env)
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Data/cache paths per §4.4, overridable by flags and `BASTION_*` env
- [x] Unit tests for precedence flag > env > default
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

```sh
make check
go test ./internal/app -run TestResolvePrecedence -v

# precedence is observable at debug level
./bin/bastion --log-level debug version
BASTION_DATA_DIR=/tmp/env-data ./bin/bastion --log-level debug --data-dir /tmp/flag-data version
BASTION_CACHE_DIR=/tmp/env-cache ./bin/bastion --log-level debug version

# spike-trivy now takes its Trivy cache from the app cache dir
./bin/bastion spike-trivy --cache-dir <base> testdata/trivy/fixture   # uses <base>/trivy
```

## Notes / Log

- Branch: `bst-005-app-paths` (from `master`).
- New package `internal/app`:
  - `Resolve(app.Flags) (app.Paths, error)` implements precedence flag >
    `BASTION_DATA_DIR`/`BASTION_CACHE_DIR` > `os.UserConfigDir()/bastion` and
    `os.UserCacheDir()/bastion` (§4.4). `Paths.DBPath()` is `<data>/bastion.db`,
    `Paths.TrivyCacheDir()` is `<cache>/trivy`.
  - `Resolve` has no filesystem side effects (creates nothing), so `bastion
    version` stays side-effect free; `Serve`/`scan` create dirs where needed.
  - Config is stdlib only. Viper stays a Trivy-only (transitive) concern; it is
    already a direct require only because `internal/scanners/trivy` resets it.
- Logging: `app.NewLogger` (text default, `--log-format json`) and
  `app.SetupLogging`, which installs bastion's handler as `slog.Default()` and
  errors if the handler did not take effect. This is the ADR-001 mitigation for
  Trivy's import-time `slog.Default()` hijack; `cmd/bastion`'s root
  `PersistentPreRunE` calls it before any subcommand work.
- Root persistent flags: `--data-dir`, `--cache-dir`, `--log-format`,
  `--log-level` (debug|info|warn|error). `rootOptions` carries the resolved
  `app.Paths` to subcommands.
- `spike-trivy` lost its own `--cache-dir` flag; it uses the root flag and the
  app cache dir, i.e. the Trivy cache is now `<cache>/trivy`. Passing
  `--cache-dir X` therefore means Trivy writes to `X/trivy` (previously X
  directly). ADR-001's measurement command needs `<base>` adjusted accordingly.
- Dependencies added: **none**.
- Verified: `make check` → 0 lint issues, all tests pass, `CGO_ENABLED=0` build
  OK. Manual: flag/env/default precedence via `--log-level debug`; `spike-trivy`
  warm run against the existing Trivy cache through `<base>/trivy` produced the
  same 8 vulnerabilities (0.43 s).
