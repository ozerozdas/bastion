# ADR-001: Trivy as an embedded Go library

- Status: proposed (spike complete, awaiting Özer's approval)
- Date: 2026-11-11
- Task: BST-003
- Deciders: Özer (human), coder agent
- Spec refs: §1.1 (single-binary core), §3 (stack), §4.2 (import rule), §10 (risks), §12 (BST-003)

## Context

Bastion's central differentiator is a **single pure-Go binary** (`CGO_ENABLED=0`) that
orchestrates proven scanners as **libraries**, not subprocesses (§1.1). The biggest
technical risk in Phase 0 is Trivy: it is a large application whose `pkg/` tree is not
a stable public API, and it could make the binary unshippable (size) or the build
unworkable (time, memory, CGO).

This ADR records a spike that answers, with measured numbers, whether Trivy
`v0.76.2` can be imported into a `CGO_ENABLED=0` binary and scan a local directory for
vulnerabilities, misconfigurations (IaC) and licenses.

Spike artifacts:

- `internal/scanners/trivy/trivy.go` — the only package importing Trivy; exposes
  `ScanFS(ctx, dir, cacheDir) (json.RawMessage, error)`.
- `cmd/bastion/spike_trivy.go` — hidden `bastion spike-trivy <dir>` entrypoint
  (superseded by `bastion scan` in BST-011).
- `testdata/trivy/fixture/` — a `package-lock.json` with `lodash@4.17.15`,
  `minimist@1.2.0` and a GPL-3.0 package, plus a `Dockerfile` running as root
  from `ubuntu:latest`.

## Measurements

Machine: macOS arm64 (Apple M4), Go toolchain 1.27.4 (module `go` directive 1.27.0),
Trivy v0.76.2, measured 2026-11-11. Every number below was produced by a command in
this session; none are estimates.

| Metric | Before (cobra only) | After (+ Trivy v0.76.2) |
|---|---|---|
| Trivy version pinned in `go.mod` | — | `v0.76.2` (exact) |
| `replace` directives needed from Trivy's `go.mod` | — | **none** (v0.76.2 has none) |
| `make build` binary size | 2,539,698 B (2.42 MiB) | **155,068,834 B (147.9 MiB / 155.1 MB)** |
| binary size delta | — | +152,529,136 B (+152.5 MB) |
| clean build time (fresh `GOCACHE`) | 1.97 s | **59.82 s** (build cache footprint 2.8 GB) |
| incremental build, no source change | 0.11 s | **1.16 s** |
| rebuild after touching `cmd/bastion/main.go` | — | **0.84 s** |
| `CGO_ENABLED=0` builds and runs | yes | **yes** (Makefile unchanged) |
| modules in `go list -m all` | 399 | **1163** |
| `go.mod` size / lines | 11,096 B / 220 | 30,151 B / 543 |
| `go.sum` size / lines | 93,289 B / 977 | 141,479 B / 1499 |
| direct requires | `cobra` | `cobra`, `trivy`, `viper` |
| vulnerability DB on disk | — | **1,759,350,784 B (1.6 GiB)** |
| misconfiguration checks bundle on disk | — | **2.6 MB** (`<cache>/policy/content`) |
| Java DB | — | **not downloaded; not needed for this fixture** (no `.jar`) |
| first run, cold cache (DB + checks download + scan) | — | **12.77 s** |
| second run, warm cache | — | **0.46 s** |
| `make check` (fmt, lint, test, build), warm cache | ~0.3 s | **42.06 s** (golangci-lint type-checks the Trivy graph) |

### Findings on `testdata/trivy/fixture`

8 vulnerabilities + 4 misconfigurations + 3 license entries, all three classes
present in one report (47,680 B of JSON):

| Class | Count | Detail |
|---|---|---|
| Vulnerabilities | **8** (1 critical, 4 high, 3 medium) | `minimist@1.2.0`: CVE-2021-44906, CVE-2020-7598. `lodash@4.17.15`: CVE-2020-8203, CVE-2021-23337, CVE-2026-4800, NSWG-ECO-516, CVE-2020-28500, CVE-2025-13465. All carry `FixedVersion`. |
| Misconfigurations | **4** (2 high, 1 medium, 1 low) | DS-0002 root user (high), DS-0029 `apt-get` without `--no-install-recommends` (high), DS-0001 `:latest` tag (medium), DS-0026 no `HEALTHCHECK` (low) |
| Licenses | **3** (1 high restricted, 2 low notice) | `gpl-fixture` GPL-3.0-only → severity high, category `restricted`; `lodash`/`minimist` MIT → low, `notice` |

The report also returns the package inventory (`Results[].Packages`) needed for §5
`packages`, and `Class`/`Type`/`Target` per result (`lang-pkgs/npm/package-lock.json`,
`config/dockerfile/Dockerfile`, `license/-/package-lock.json`).

## Decision

**Accepted: Trivy is used as an embedded Go library, pinned to `v0.76.2`, behind
`internal/scanners/trivy`.**

Rationale:

1. It works. `CGO_ENABLED=0` builds a single binary that produces vulnerabilities,
   misconfigurations and licenses from one call, with no subprocess and no Docker.
2. The binary is **148 MiB / 155.1 MB**, marginally above the `~150 MB` exit gate in
   §8/§10. The gate is approximate ("<~150 MB (record actual)"), and the actual
   number is now recorded. Growth per feature after this point should be small: the
   Trivy dependency graph is the bulk and is already paid.
3. **There are no build tags to trim Trivy.** A grep of every non-test `//go:build`
   line in v0.76.2 yields only `wasip1`, `unix`, `!windows`, `ruleguard` and mage
   targets. `pkg/fanal/analyzer/all` (which links every language and IaC analyzer) is
   imported unconditionally by `pkg/commands/artifact`, and the IaC/OPA/Terraform
   stack has no opt-out. The §10 mitigation "build tags to drop unused analyzers" is
   therefore **not available** in this version; trimming would require bypassing
   `pkg/commands/artifact` and wiring a private scan service from unstable internals,
   which is a worse risk than 5 MB of binary.
4. Startup and warm scans are fast (0.46 s), so embedding does not hurt the
   "first report in 5 minutes" goal.

Fallback (not taken, kept on the shelf): download a pinned, checksum-verified Trivy
binary into the cache dir and run it as a subprocess, exactly like ADR-002's SAST
module. It removes ~150 MB and the build-time cost, at the price of losing the
single-binary promise and adding an opt-in download. Revisit only if binary size,
cold build time (≈60 s, 2.8 GB of build cache) or the linter/type-check cost become a
product or CI problem.

### go.mod consequences

- `github.com/aquasecurity/trivy v0.76.2` (exact). No `replace` directives are needed.
- **Go minimum raised to 1.27.0.** Trivy v0.76.2 declares `go 1.27.0`; `go get` bumped
  our directive from `1.26.0`. Approved by Özer (spec §3 says "Go 1.26+"; the spec will
  say 1.27+). v0.74.0 is the last release buildable with Go 1.26 if that is ever needed.
- `github.com/spf13/viper v1.21.0` becomes a direct dependency: `newOptions` must
  reset Viper between scans (Trivy reads all flags through the global instance).
- Adding Trivy forced `github.com/gobwas/glob` from v0.2.3 to **v1.0.0**, which broke
  two of golangci-lint's own analyzers (`depguard v2.2.1`, `protogetter v1.0.1`, both
  `undefined: glob.Glob`). Fixed by upgrading those indirect modules to the versions
  that target glob v1.0.0: `depguard v2.3.0`, `protogetter v1.0.2`. Neither linter is
  enabled in `.golangci.yml`; they only had to compile.

## Consequences

1. **`slog.Default()` is hijacked at import time.** Trivy's `pkg/log` package runs an
   `init()` that installs a *buffering* `slog` handler; anything logged before
   `log.InitLogger` is queued and then silently dropped. Since Go runs all package
   `init()`s before `main()`, importing Trivy means bastion's own `slog` output can
   disappear.
   **Mitigation:** `cmd/bastion` (and later `internal/app`) must call
   `slog.SetDefault(...)` with bastion's handler before doing work. The spike does this
   in `spike-trivy`'s `RunE`; the effect is that Trivy's diagnostics appear in
   bastion's own log format on stderr. Add a startup assertion in `internal/app`
   (BST-005) so a future refactor cannot lose logging silently.

2. **Trivy's configuration is process-global.** `flag.Options` is built by parsing
   Trivy's own flags into the global Viper instance, and the vulnerability DB handle,
   Java DB updater and WASM module manager are singletons.
   **Mitigation:** `ScanFS` takes a package-level mutex and calls `viper.Reset()` on
   every run, so repeated scans in one process are correct but **serialized**. The
   worker pool (BST-010 / Phase 1, default concurrency 2) must either accept
   serialization for Trivy scans or run each scan in its own process; do not remove
   the lock without re-auditing Trivy's globals. Gitleaks is unaffected and can run in
   parallel with a Trivy scan.

3. **The import boundary is load-bearing.** §4.2 says only
   `internal/scanners/trivy` may import Trivy. Enforce it with a lint rule
   (`depguard` is already in the module graph) so a future adapter does not start
   using `types.Report` directly.

4. **API stability.** The seam we depend on is
   `pkg/commands/artifact.{NewRunner,Runner.ScanFilesystem,Runner.Filter,Runner.Report,
   Runner.Close}` plus `flag.{Flags,NewXFlagGroup,Options}` and
   `Options.SetOutputWriter`. `Runner` is explicitly documented for library use
   ("It is useful when Trivy is imported as a library" on `WithInitializeService`), but
   Trivy publishes no compatibility promise for `pkg/`. Known sharp edges measured in
   this spike:
   - `Flags.AddFlags`/`Flags.Bind` silently skip the `Global` flag group (the Trivy CLI
     registers those on its root command), so `--cache-dir` must be added and bound
     separately, while `ToOptions` still walks the full slice. Upgrade hazard.
   - A positional argument is what sets the scan target (`opts.args[0]`), not a flag.
   - `Metadata.Version` in the JSON report is `null` because `AppVersion` is derived
     from the *host* binary's build info. `scanner_runs.scanner_version` must use
     `trivy.Version` (our constant) instead.
   **Mitigation (already planned):** exact version pin; upgrade only as a dedicated
   task with a golden-test diff on the raw JSON (BST-011), per §10.

5. **First run downloads ~1.8 GB of database**, not megabytes. On this machine the
   cold run took 12.77 s, but that is a fast network; §10's "show progress in UI,
   cache, `--offline`" mitigation is necessary, and `bastion doctor` (BST-012) should
   report DB age/size. The 1.6 GiB DB also means the cache dir, not the binary, is the
   large artifact on a user's disk.

6. **Build and CI cost.** A cold `CGO_ENABLED=0` build needs ≈60 s and 2.8 GB of
   `GOCACHE`; `make check` grows to 42 s because golangci-lint type-checks the Trivy
   graph. Acceptable for CI, but contributors on small disks need a build cache
   outside the system volume (observed here: a 2.6 GiB-free system volume failed with
   `ENOSPC` mid-build).

7. **Secrets stay out of Trivy.** Scanners are fixed to `vuln,misconfig,license`;
   Trivy's secret scanner is never enabled because Gitleaks owns secrets (§3), and
   Trivy's secret findings would duplicate Gitleaks with a different severity model.

## Verification commands

```sh
# deps / pin
go list -m all | wc -l
grep 'aquasecurity/trivy' go.mod

# size + build
make build && stat -f '%z bytes' bin/bastion
GOCACHE=$(mktemp -d /Volumes/Krypton/.cache/gocache-XXXX) make build   # clean build
make build                                                              # incremental
make check

# spike, cold then warm (cache dir on a large volume; ~1.6 GiB DB)
T=$(mktemp -d /Volumes/Krypton/.cache/bastion-trivy-XXXX)
time ./bin/bastion spike-trivy --cache-dir "$T" testdata/trivy/fixture > "$T/cold.json"
time ./bin/bastion spike-trivy --cache-dir "$T" testdata/trivy/fixture > "$T/warm.json"
du -sh "$T/db" "$T/policy"

# findings per class
jq -r '[.Results[] | .Vulnerabilities // [] | length] | add' "$T/cold.json"
jq -r '[.Results[] | .Misconfigurations // [] | length] | add' "$T/cold.json"
jq -r '[.Results[] | .Licenses // [] | length] | add' "$T/cold.json"
```
