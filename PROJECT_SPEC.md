# Bastion — Local Security Center — Project Spec

> Single source of truth for the agent swarm. Read this file fully before planning or writing code.
> Task management lives under `.pm/` (rules in §11). If this spec and a task file disagree, this spec wins; raise the conflict in `.pm/decisions/`.

---

## 1. Vision

A **local-first, open-source security center** for developers. One binary, run on your own machine, opens a clean web UI in the browser, connects to GitHub, AWS ECR and Docker, and reports dependency vulnerabilities, leaked secrets, image vulnerabilities and SBOMs in one place.

It does **not** build its own security engine. It orchestrates proven open-source scanners (Trivy, Gitleaks; later OSV-Scanner, Grype, Syft) behind a modular interface, normalizes their output into one data model, and turns findings into **actionable, prioritized steps**.

Positioning: a free, private, simple alternative to paid platforms like Aikido.dev for individual developers and small teams.

### Differentiators (must stay true in every phase)
1. **Single-binary core.** Core scanners (Trivy, Gitleaks, later OSV-Scanner, govulncheck) are imported as Go libraries, not shelled out. No Docker, no Python, no external CLI required for the core. `CGO_ENABLED=0`. Optional modules with no Go library (SAST via Opengrep) are downloaded only on explicit opt-in into the cache dir, version-pinned and checksum-verified (ADR-002). The core works fully without them.
2. **Nothing leaves the machine** except calls the user explicitly configured (GitHub API, AWS API, vulnerability DB downloads, opt-in module downloads). No telemetry. Optional LLM features talk only to a local model server (Ollama on localhost, ADR-003).
3. **Repo ↔ image lineage.** Show which GitHub repo produces which ECR image and what is vulnerable in the deployed tag.
4. **Actionable output.** "Upgrade package X to Y → closes N findings", not just a CVE list.
5. **Agent-friendly.** MCP server (Phase 4) so AI agents can query findings and propose fixes, and compose with artifact-analysis tools such as REA (`morluto/rea`) without bastion embedding them.
6. **Less noise than SaaS.** Use local compute for what hosted platforms ration: malicious-package detection (Phase 2), reachability analysis (Phase 3), full git-history secret scans (Phase 5).

### Non-goals (v1)
- Multi-user, auth, RBAC, hosted/SaaS mode
- Continuous monitoring while the app is closed (explicit trade-off of local-first; server mode is Phase 5)
- DAST, cloud posture (CSPM), runtime security
- SAST inside the core binary (it is an opt-in downloaded module, Phase 3)
- Writing our own vulnerability matching logic

---

## 2. Users & core flow

**Primary user:** a developer or tech lead responsible for a handful to a few dozen repos and images.

**Core flow (v0.1):**
1. `./bastion` → server starts on `127.0.0.1:<random port>` → browser opens automatically.
2. Connections page → add GitHub token (stored in OS keychain).
3. Projects page → list repos → select some → "Scan".
4. Scan progress streams live (SSE).
5. Dashboard shows totals and severity distribution; Security Reports shows findings grouped by project and by fix.

**Success criterion for v0.1:** a new user gets their first report within 5 minutes of downloading the binary.

---

## 3. Tech stack (decided — changes require an ADR)

| Area | Choice | Notes |
|---|---|---|
| Language | Go 1.27+ (forced by Trivy v0.76, ADR-001) | `CGO_ENABLED=0` for all builds. Dev tools pinned via `tool` directives in a separate `tools/go.mod` (`go tool -modfile=tools/go.mod <name>`), no global installs |
| HTTP | stdlib `net/http` (1.22+ routing) | No web framework |
| CLI | `spf13/cobra` | `bastion serve` (default), `bastion scan`, `bastion doctor`, `bastion version` |
| Logging | `log/slog` | JSON in `--log-format json`, text by default |
| DB | SQLite via `modernc.org/sqlite` | Pure Go. WAL mode. One file in user data dir |
| Queries | `sqlc` | No ORM |
| Migrations | `pressly/goose` | Embedded in binary, run on startup |
| API contract | OpenAPI 3.1 (`api/openapi.yaml`) | Go: `oapi-codegen` (std http server). TS: `openapi-typescript` |
| Jobs | In-process worker pool | Scan state persisted in SQLite; progress via SSE |
| Vulnerabilities / SBOM | Trivy as library (`github.com/aquasecurity/trivy/pkg/...`) | Pin exact version; wrap behind our `Scanner` interface |
| Secrets | Gitleaks v8 as library (`detect` package) | |
| GitHub | `google/go-github` | Repo list, tarball download |
| AWS | `aws-sdk-go-v2` (`config`, `ecr`, `sts`) | Uses the user's existing AWS profiles / SSO |
| Images | `google/go-containerregistry` | Pull from ECR / registries without a Docker daemon |
| Local Docker (Phase 2) | Docker Engine API client | Optional; only if daemon present |
| Secrets storage | `zalando/go-keyring` | macOS Keychain, Windows Credential Manager, Linux Secret Service. **Never** store tokens in SQLite |
| Open browser | `pkg/browser` | |
| Frontend | React + TypeScript + Vite | |
| Data fetching | TanStack Query | |
| Routing | TanStack Router | |
| UI | Tailwind CSS + shadcn/ui | Minimal, calm, dense-but-readable |
| Charts | Recharts | |
| Embedding | `go:embed` of `web/dist` | |
| Release | GoReleaser | darwin/linux/windows × amd64/arm64, Homebrew tap, `install.sh` |
| CI | GitHub Actions | test, `golangci-lint`, build, self-scan with `bastion scan` |
| License | Apache-2.0 | Compatible with Trivy (Apache-2.0) and Gitleaks (MIT) |

---

## 4. Architecture

```
            ┌─────────────── bastion (single binary) ───────────────┐
 Browser ──▶│ HTTP server (127.0.0.1, token-guarded)            │
 (React UI) │   ├── /api/*  (OpenAPI handlers)                   │
            │   ├── /api/events (SSE)                            │
            │   └── /*  embedded SPA                             │
            │                                                    │
            │ Services                                           │
            │   ├── connections  (GitHub, AWS, Docker; keyring)  │
            │   ├── sources      (fetch target → local workspace)│
            │   ├── jobs         (worker pool, scan lifecycle)   │
            │   ├── scanners     (Scanner interface + adapters)  │
            │   ├── findings     (normalize, fingerprint, diff)  │
            │   └── reports      (aggregations, fix grouping)    │
            │                                                    │
            │ Store: SQLite (sqlc)   Cache: vuln DBs, workspaces │
            └────────────────────────────────────────────────────┘
```

### 4.1 Repository layout
```
cmd/bastion/                 main.go, cobra commands
internal/app/            wiring, config, paths (data dir, cache dir)
internal/httpapi/        generated server + handlers, SSE, auth middleware
internal/store/          sqlc generated code + store wrapper
internal/connections/    github, aws, docker connection management
internal/secrets/        keyring wrapper (interface + fake for tests)
internal/sources/        github (tarball), ecr, registry, localpath
internal/scanners/       scanner.go (interface), trivy/, gitleaks/
internal/findings/       model.go, normalize.go, fingerprint.go, diff.go
internal/jobs/           queue, worker pool, lifecycle
internal/reports/        dashboard aggregations, fix grouping
api/openapi.yaml
db/migrations/           goose SQL files
db/queries/              sqlc query files
web/                     Vite React app
testdata/                golden files: raw scanner output → expected findings
.pm/                     task management (see §11)
```

### 4.2 Core interfaces (Go)
```go
// internal/sources
type TargetKind string // "repo" | "image" | "path"

type Target struct {
    Kind     TargetKind
    AssetID  int64
    Ref      string // "owner/repo@sha", "123.dkr.ecr.eu-west-1.amazonaws.com/app:1.4.2", "/abs/path"
}

type Workspace struct {
    Dir     string       // for repo/path targets
    Image   v1.Image     // for image targets (go-containerregistry)
    Cleanup func() error
}

type Source interface {
    Kind() TargetKind
    Fetch(ctx context.Context, t Target) (*Workspace, error)
}

// internal/scanners
type Scanner interface {
    Name() string                       // "trivy", "gitleaks"
    Version() string
    Supports(k sources.TargetKind) bool
    Scan(ctx context.Context, ws *sources.Workspace, opts Options) (*RawResult, error)
}

// internal/findings
type Normalizer interface {
    Normalize(raw *scanners.RawResult, asset Asset) ([]Finding, []Package, error)
}
```
Rule: **no package outside `internal/scanners/<name>/` may import that scanner's library.** This keeps Trivy's unstable internal API contained.

### 4.3 Local server security (non-negotiable)
- Bind to `127.0.0.1` only. Random free port unless `--port` given.
- On start, generate a random session token; open browser at `http://127.0.0.1:<port>/?t=<token>`. The server exchanges it for an `HttpOnly; SameSite=Strict` cookie and immediately sends the browser on to the same URL without `t` via a page-level refresh (not 303, which keeps the cross-site context of a link opened from another app, so the Strict cookie would not be sent), so the token does not stay in the address bar or history. The token is single-use. All `/api/*` requests require the cookie.
- Reject requests whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding).
- No CORS. CSRF: require custom header `X-Bastion: 1` on mutating requests.
- Tokens/keys never returned by the API, never logged. Log redaction helper for anything credential-shaped.
- Gitleaks findings store a **redacted** match (first 4 chars + `****`) and `HMAC-SHA256(local_key, secret)`. `local_key` is a random 32-byte key created on first run and stored in the OS keyring (env fallback per §10). A plain hash is not allowed: low-entropy secrets would be brute-forceable from the DB. Raw secrets are never persisted.
- **Analyzed content is data, never instructions.** Anything read from a scanned target (file contents, package metadata, scanner descriptions, artifact strings) that reaches an LLM or an MCP response is wrapped and labelled as untrusted. Analyzers run with explicit size/time budgets and report partial coverage instead of failing silently.

### 4.4 Paths
- Data: `os.UserConfigDir()/bastion/bastion.db`
- Cache: `os.UserCacheDir()/bastion/` (trivy DB, java DB, workspaces)
- Workspaces are temporary and deleted after each scan (unless `--keep-workspace`).

---

## 5. Data model

All timestamps UTC, stored as RFC3339 text. IDs are integer autoincrement.

### Tables
**connections**
`id, kind (github|aws|docker), name, config_json (non-secret: org, region, profile, registry ids), secret_ref (keyring key or null), status (ok|error|unknown), last_checked_at, created_at`

**assets** — anything we scan
`id, kind (repo|image|path), connection_id (nullable), display_name, ref (canonical: owner/repo, registry/repo), default_branch, metadata_json, created_at, archived_at`

**asset_links** — repo ↔ image lineage (Phase 2)
`id, repo_asset_id, image_asset_id, source (manual|label|heuristic), created_at`

**scans** — one user-triggered scan of one asset
`id, asset_id, target_ref (resolved sha or digest), status (queued|running|succeeded|failed|canceled), trigger (ui|cli|api), started_at, finished_at, error`

**scanner_runs** — one scanner within a scan
`id, scan_id, scanner, scanner_version, db_version, status, duration_ms, error, raw_path (optional, for debug)`

**packages** — SBOM entries per scan
`id, scan_id, ecosystem (npm|go|composer|pypi|maven|os-apk|os-deb|…), name, version, purl, path, direct (bool|null)`

**findings** — normalized, one row per finding per scan
`id, scan_id, asset_id, type (vulnerability|secret|outdated|misconfig|license|malware|sast), fingerprint, severity (critical|high|medium|low|unknown), title, rule_id (CVE/GHSA/gitleaks rule), package_name, package_version, fixed_version, ecosystem, location (file:line or layer), cvss, epss (Phase 3), description, references_json, scanner, first_seen_scan_id, status (open|ignored), created_at`

**finding_states** — user decisions that survive across scans (keyed by fingerprint)
`id, asset_id, fingerprint, state (ignored|accepted_risk|false_positive), reason, created_at`

### Fingerprint (critical for diff & dedup)
`sha256(asset_id | type | rule_id | ecosystem | package_name | location_normalized)`, where each field is encoded unambiguously as `<byte length>:<value>` (a plain `|` join lets a `|` inside a field collide with a different split).
- **One finding per fingerprint per scan.** Occurrences that share a fingerprint inside one scan (same CVE on two copies of a package in one lockfile, the same Dockerfile rule in two stages) are merged into one finding: highest severity wins, `occurrences` counts them. Line numbers are deliberately not used to split them, since they would make fingerprints unstable.
- **Excludes** `package_version` and `scan_id`, so the same CVE on the same package stays the same finding after an unrelated bump. A version change that fixes it makes it disappear → "closed".
- `location_normalized` strips temp workspace prefixes and, for secrets, uses `file + rule_id + secret_hmac` (not line number, which shifts).
- For **image** targets, `location_normalized` is the package's file path inside the image (e.g. `usr/lib/node_modules/x/package.json`, or the OS package DB path for OS packages), **never the layer digest**: layer digests change on every rebuild and would make every finding look new and fixed at once.
- For **misconfig**, location is `file + resource/cause identifier`, not line number.

### Diff between two scans of the same asset
- **new** = fingerprints in B not in A
- **fixed** = fingerprints in A not in B
- **persisting** = in both
Implemented in `internal/findings/diff.go` with golden tests.

---

## 6. API (outline — authoritative contract is `api/openapi.yaml`)

```
GET    /api/health
GET    /api/connections
POST   /api/connections                 {kind, name, config, secret}
POST   /api/connections/{id}/test
DELETE /api/connections/{id}
GET    /api/connections/{id}/discover   → repos / ECR repositories / images available to add
GET    /api/assets
POST   /api/assets                      {kind, connection_id, ref}
DELETE /api/assets/{id}
POST   /api/scans                       {asset_ids[]}
GET    /api/scans?asset_id=&limit=
GET    /api/scans/{id}
POST   /api/scans/{id}/cancel
GET    /api/scans/{id}/findings?type=&severity=&status=
GET    /api/scans/diff?from={id}&to={id}
GET    /api/findings?asset_id=&severity=&type=     (latest scan per asset)
POST   /api/findings/{fingerprint}/state            {state, reason}
GET    /api/reports/dashboard
GET    /api/reports/fixes?asset_id=                 (Phase 3)
GET    /api/scans/{id}/sbom?format=cyclonedx        (Phase 2)
GET    /api/events                                  SSE: scan.queued|scan.progress|scan.finished
```
Errors: RFC 9457 problem+json.

---

## 7. UI

Five sections, left nav. Calm, minimal, dark + light themes. Severity colors used sparingly (badges and charts only).

1. **Dashboard** — totals by severity (critical/high/medium/low), findings by type, top 5 riskiest projects, trend of open critical+high over recent scans, last scan time per asset.
2. **Connections** — cards for GitHub / AWS / Docker; add, test, remove. Shows status and which identity it is (GitHub login, AWS account id via STS).
3. **Projects** — table of assets with last scan status, severity counts, "Scan" action; "Add projects" opens discover dialog with search + multi-select.
4. **Security Reports** — per asset: findings table (filter by type/severity/status), finding detail drawer (description, fixed version, references, ignore with reason). Phase 3: "Fix plan" tab grouping by package upgrade.
5. **Scan History** — list of scans; select two to see diff (new / fixed / persisting).

Empty states must explain the next step. Every scan error must show a human-readable cause and a suggested fix (e.g. "AWS SSO session expired → run `aws sso login --profile X`").

---

## 8. Phases

Each phase ends with a tagged release and a short demo (GIF or video) in the README.

### Phase 0 — Spec & skeleton (target: 1–2 weeks)
Goal: **retire the biggest technical risk** (Trivy + Gitleaks as libraries inside a pure-Go single binary) before building features.
- Repo scaffold per §4.1, Makefile/Taskfile, golangci-lint, CI
- Spike: Trivy library scans a local directory (filesystem/SCA) → print findings. **Measure binary size and build time; record in ADR-001.**
- Spike: Gitleaks library scans a local directory
- SQLite + goose + sqlc wired, first migration with all tables in §5
- HTTP server with security in §4.3, embedded "hello" SPA, browser auto-open
- OpenAPI file with `/api/health`, codegen pipeline for Go + TS working
- `bastion doctor` prints paths, versions, keyring availability, DB status

**Exit criteria:** `make build` → one binary <~150 MB (record actual) that starts, opens the browser, and `bastion scan --path .` prints normalized findings from both scanners to stdout as JSON.

### Phase 1 — Core MVP (v0.1)
- GitHub connection (PAT; token in keyring; test via `GET /user`)
- Discover + add repos; fetch via tarball download of default branch HEAD (resolve SHA first)
- Scan jobs: worker pool (default concurrency 2), SSE progress, cancel
- Trivy (vulnerabilities + package inventory + misconfig/IaC + licenses) and Gitleaks (working-tree secrets) adapters + normalizers. License findings in v0.1 are informational; allow/deny policy comes in Phase 3
- Fingerprinting, findings persistence, finding_states (ignore with reason)
- UI: Dashboard, Connections (GitHub), Projects, Security Reports, Scan History (list only)
- `bastion scan --repo owner/name --format json|table|sarif` for CLI use
- README with quickstart, demo GIF, threat model section

**Exit:** 5-minute first report on a fresh machine; golden tests for both normalizers; self-scan in CI.

### Phase 2 — Containers & diff (v0.2)
- AWS connection (profile/SSO via default credential chain; identity via STS)
- ECR discovery (repositories, recent tags with digests), image scan via go-containerregistry → Trivy image scan
- Local Docker image scan (optional, if daemon present)
- Scan diff UI and API
- Repo ↔ image links: manual first; then auto from OCI labels (`org.opencontainers.image.source`, `org.opencontainers.image.revision`)
- SBOM export (CycloneDX JSON) per scan
- OSV-Scanner adapter (library): malicious-package detection (`MAL-` advisories → `malware` findings, severity critical) and vulnerability cross-check; dedup with Trivy by (ecosystem, package, advisory alias set)

**Exit:** used for real at work on actual ECR images; diff verified on two real scans.

### Phase 3 — Actionable output (v0.3)
- Fix plan: group vulnerability findings by (package, minimal fixed version) → "upgrade X to Y closes N (C critical, H high)"
- Prioritization score: severity × fix available × EPSS (FIRST.org feed, cached, opt-in download) × "in latest image tag"
- **Outdated packages** (opt-in, clearly labeled as an outbound call): latest-version lookup via deps.dev or ecosystem registries. Only package names/versions are sent. Off by default.
- Better ignore workflow: bulk ignore, expiry date for accepted risk
- Reachability: govulncheck (library) for Go modules marks vulnerabilities `reachable|unreachable|unknown`; feeds the prioritization score. Other ecosystems later
- SAST as opt-in module (ADR-002): pinned Opengrep binary downloaded on demand, checksum-verified, output normalized to `sast` findings
- License policy: allow/deny lists, global or per asset

### Phase 4 — AI & automation (v0.4)
- MCP server (`bastion mcp` stdio + optional HTTP): tools `list_assets`, `list_findings`, `get_fix_plan`, `diff_scans`, `trigger_scan`
- Open dependency-upgrade PRs on GitHub from a fix plan (user confirms each PR)
- Notifications: Slack webhook, email (SMTP) on new critical/high
- Optional local LLM (ADR-003): off by default; when enabled, talks only to a localhost OpenAI-compatible endpoint (Ollama). Uses: finding triage summary, fix-plan explanation. Target content always passed as untrusted data (§4.3)
- Agent composition: ship an agent skill that combines `bastion mcp` with REA for shipped-artifact questions (binary hardening, bundled source maps, endpoints in JS bundles). REA is never embedded in the bastion binary
- Adversarial test corpus: BLA-hardened artifacts (`qybaihe/bla`) verify that MCP/LLM paths respect budgets and do not follow instructions embedded in targets
- GitHub Action: `bastion scan` in CI, SARIF upload, fail on threshold

### Phase 5 — Later
- Additional scanners: Grype, Syft (with cross-scanner dedup)
- Git history secret scanning (go-git clone)
- Server mode: scheduled scans, multi-user, auth
- License compliance findings

---

## 9. Engineering rules for agents

1. **Spec-first.** Any change to API shape → edit `api/openapi.yaml` first, regenerate, then implement. Any change to schema → new goose migration + sqlc query, never edit applied migrations.
2. **Boundaries.** Respect §4.2 import rule. Handlers stay thin; logic lives in services.
3. **Errors.** Wrap with context (`fmt.Errorf("fetch tarball %s: %w", ref, err)`). User-facing errors carry a hint.
4. **Context everywhere.** All I/O takes `context.Context`; scans must be cancelable.
5. **Tests.**
   - Normalizers and diff: golden tests in `testdata/` (raw → expected JSON). Update goldens only with `-update` flag and explain why in the task log.
   - Store: tests against a temp SQLite file.
   - External APIs (GitHub, AWS): interfaces + fakes; no live calls in unit tests.
   - Frontend: Vitest for logic, Playwright smoke test for the 5 pages (Phase 1+).
6. **Security.** Never log, persist or return secrets. Any new outbound network call needs an ADR and must be listed in README "Network calls" section.
7. **Dependencies.** Adding a Go or npm dependency requires a one-line justification in the task log. Prefer stdlib.
8. **Definition of Done (every task):**
   - Acceptance criteria in the task file all checked
   - `make check` passes (fmt, lint, test, build)
   - Docs updated if behavior or API changed
   - Task file status set to `review` with a summary of changes and verification commands run

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Trivy library makes binary huge / build slow | Measured in Phase 0 (ADR-001). Fallback: build tags to drop unused analyzers; last resort: managed external Trivy binary download |
| Trivy internal API breaks on upgrade | Pin version; all usage behind `internal/scanners/trivy`; upgrade = dedicated task with golden test diff review |
| Vuln DB download is large/slow on first run | Show progress in UI; cache; `--offline` flag uses existing cache |
| Keyring unavailable (headless Linux) | Detect in `bastion doctor`; fallback to env vars (`BASTION_GITHUB_TOKEN`), never to plaintext file |
| False positives erode trust | Ignore with reason, persisted by fingerprint; show scanner + rule for every finding |
| Local-first means no monitoring when closed | Documented as trade-off; CI integration (Phase 4) and server mode (Phase 5) cover it |
| Scope creep | Phase exit criteria are hard gates; new ideas go to `.pm/backlog.md`, not into current phase |

---

## 11. Task management (`.pm/`)

### 11.1 Structure
```
.pm/
  BOARD.md            index of all tasks: id | title | phase | status | owner_role | depends_on
  backlog.md          unscheduled ideas (one line each)
  phases/
    P0.md … P5.md     phase goal, exit criteria, task list (ids)
  tasks/
    BST-001-repo-scaffold.md
    …
  decisions/
    ADR-001-trivy-as-library.md
    …
  log/
    YYYY-MM-DD.md     session log: what was done, by which role, open questions
```

### 11.2 Task file template
```markdown
---
id: BST-012
title: Gitleaks adapter and normalizer
phase: P1
status: todo        # todo | ready | in_progress | review | done | blocked
owner_role: coder   # architect | coder | reviewer | tester
depends_on: [BST-004, BST-010]
estimate: S         # S (<2h) | M (half day) | L (1–2 days) — split anything bigger
---

## Context
Why this exists; link to spec section (e.g. §4.2, §5).

## Scope
- In: …
- Out: …

## Acceptance criteria
- [ ] …
- [ ] Golden test `testdata/gitleaks/basic` passes
- [ ] `make check` passes

## Verification
Commands the reviewer runs.

## Notes / Log
Agent appends decisions, deps added, open questions.
```

### 11.3 Workflow
1. **Architect** picks the next phase, breaks it into tasks (S/M/L, nothing larger than L), writes task files, sets `depends_on`, marks unblocked ones `ready`, updates `BOARD.md`.
2. **Coder** takes one `ready` task at a time → `in_progress` → implements → runs verification → `review` with summary.
3. **Reviewer** checks against acceptance criteria and §9 rules → `done` or back to `in_progress` with comments in the task's Notes.
4. **Tester** owns golden data, Playwright smoke tests and phase exit verification.
5. Anything that changes this spec, the stack, the schema shape, or adds a network call → `decisions/ADR-xxx.md` first, human (Özer) approves.
6. Each session ends with a `log/YYYY-MM-DD.md` entry and an updated `BOARD.md`.
7. One task = one local branch (`bst-012-gitleaks-adapter`) with commits, merged into `master` locally. Agents never push; the human pushes and opens PRs.

---

## 12. Seed tasks — Phase 0

| ID | Title | Est | Depends on |
|---|---|---|---|
| BST-001 | Repo scaffold: layout §4.1, go.mod, Makefile (`build`, `check`, `gen`), golangci-lint config, .editorconfig, Apache-2.0 LICENSE | S | — |
| BST-002 | CI: GitHub Actions running `make check` on push/PR (linux), build matrix smoke | S | 001 |
| BST-003 | ADR-001 spike: Trivy library filesystem scan (vuln + misconfig + license) of a local dir → stdout JSON. Record binary size, build time, Trivy version, DB size, first-run time | M | 001 |
| BST-004 | Spike: Gitleaks library scan of a local dir → stdout JSON, with redaction | S | 001 |
| BST-005 | `internal/app` paths + config (data dir, cache dir, flags, env) | S | 001 |
| BST-006 | SQLite (modernc) + goose embedded migrations + sqlc setup; migration 0001 with all §5 tables | M | 005 |
| BST-007 | OpenAPI file with `/api/health`; `make gen` runs oapi-codegen + openapi-typescript | S | 001 |
| BST-008 | HTTP server: localhost bind, random port, token→cookie exchange, Host check, `X-Bastion` header check, slog request logging with redaction | M | 007 |
| BST-009 | Web scaffold: Vite + React + TS + Tailwind + shadcn + TanStack Query/Router; layout with 5 nav items (placeholder pages); build to `web/dist`; `go:embed` serving with SPA fallback | M | 008 |
| BST-010 | Scanner interface + findings model (§4.2, §5) + fingerprint function with unit tests | M | 003, 004 |
| BST-011 | `bastion scan --path <dir> --format json` using both spikes through the interface + normalizers (golden tests) | M | 010 |
| BST-012 | `bastion doctor` | S | 005, 006 |
| BST-013 | Keyring wrapper with interface + in-memory fake; doctor reports availability | S | 005 |
| BST-014 | Phase 0 exit check: fresh clone → `make build` → run → browser opens → `bastion scan --path .` works; record results in `phases/P0.md` | S | all above |

## 13. Phase 1 epics (architect breaks into tasks at start of P1)
- E1 GitHub connection & discovery
- E2 Repo source (tarball fetch, SHA resolution, workspace cleanup)
- E3 Job system (queue, worker pool, cancel, SSE)
- E4 Persistence of scans/findings/packages + finding_states
- E5 Dashboard & reports aggregations API
- E6 UI pages (Dashboard, Connections, Projects, Reports, History list)
- E7 CLI `scan --repo`, SARIF output
- E8 README, quickstart, demo GIF, threat model, "Network calls" section
- E9 Release pipeline (GoReleaser, Homebrew tap, install.sh) → tag v0.1.0
