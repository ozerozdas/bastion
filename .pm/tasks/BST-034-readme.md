---
id: BST-034
title: "README: quickstart, threat model, network calls, demo GIF"
phase: P1
status: done
owner_role: coder
depends_on: [BST-027, BST-028, BST-031]
estimate: M
---

## Context
§8 Phase 1, E8, §9.6.

## Scope
- In: what/why, install, 5-minute quickstart, CLI usage, "Network calls" (Trivy DB, GitHub per ADR-005; nothing else), threat model (localhost, token/cookie, Host check, CSRF header, secrets handling, untrusted content), demo GIF.

## Acceptance criteria
- [x] Every outbound call in code is listed (grep for `http.` clients)

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

**Done:** `README.md` created (only file added; no other paths touched). Sections: what/why,
Status, Install from source, 5-minute quickstart, CLI (all flags), Network calls, Threat
model (what it does / what it does not), Data & paths, Development, License (Apache-2.0,
`LICENSE` verified).

**Demo GIF:** deferred to BST-036 (recorded at v0.1.0). README carries only the placeholder
`<!-- demo GIF: recorded at v0.1.0 (BST-036) -->`; no image was fabricated.

**Facts verified by grep (all exist in code):**
- Commands/flags — `cmd/bastion/main.go` (`--data-dir`, `--cache-dir`, `--log-format`,
  `--log-level`, `version`), `serve.go` (`--port`, `--no-browser`, `--concurrency`,
  default `jobs.DefaultConcurrency = 2` in `internal/jobs/jobs.go:33`), `scan.go`
  (`--path`, `--repo owner/name[@ref]`, `--format json|table|sarif`, `--fail-on
  critical|high|medium|low`, `--skip-dirs`, `--no-store`; exit 2 on `--fail-on` breach),
  `doctor.go` (`--json`).
- Env vars — `internal/app/app.go:16,19` (`BASTION_DATA_DIR`, `BASTION_CACHE_DIR`),
  `internal/secrets/localkey.go:19` (`BASTION_HMAC_KEY`), `internal/connections/service.go:42`
  key `github-token` → `BASTION_GITHUB_TOKEN` via `secrets.EnvVarName` (`internal/secrets/env.go:11`).
- Paths — `internal/app/app.go`: `<config>/bastion/bastion.db`, `<cache>/bastion/trivy`,
  `<cache>/bastion/workspaces`. Workspace removal: `internal/sources/github/github.go:157`.
- Network — `grep -rn 'https://\|http\.Client\|http\.Get\|http\.NewRequest' --include='*.go'
  internal/ cmd/` (excluding tests) yields only `api.github.com`
  (`internal/connections/github/client.go:28`) and the SARIF schema URI (a string, not a
  call). GitHub redirect to `codeload.github.com` (`client.go:255`). Trivy registry defaults
  read from the pinned module v0.76.2: `pkg/db/db.go:31,35`,
  `pkg/javadb/client.go:31,34`, `pkg/policy/policy.go:24-25`; the adapter sets no override
  and passes `--disable-telemetry`/`--skip-version-check` (`internal/scanners/trivy/trivy.go`).
- Security — `internal/httpapi/middleware.go` (Host 421, single-use token → 303,
  `HttpOnly`/`SameSite=Strict`, `X-Bastion` CSRF, `nosniff`/`DENY`/`no-referrer`),
  `internal/httpapi/ui.go:98` (`default-src 'self'`), `internal/secrets/*` (keyring + env
  fallbacks), `internal/scanners/gitleaks/gitleaks.go` (first-4-chars redaction + HMAC).
- Budgets — `client.go:31` (512 MiB tarball), `internal/sources/github/github.go:28,31`
  (2 GiB / 200k files).
- Size/timings — `.pm/phases/P0.md` (163,738,002 B ≈ 156.2 MiB; ~1.7 GB DB; 17 s cold scan).
- UI labels — `web/src/pages/projects.tsx` ("List repositories", "Add a local path",
  "Scan"), `reports.tsx` (Ignored / Accepted risk / False positive, reason required),
  `connections.tsx` (fine-grained *Contents: read* + *Metadata: read*).
- Toolchain — `go.mod` `go 1.27.0`; CI `node-version: 24`; `web/package.json` engines `>=22.12`.
