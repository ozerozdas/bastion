# Bastion

Local-first security center. One Go binary, run on your own machine, that opens a web UI
in your browser and reports dependency vulnerabilities, licence issues, IaC
misconfigurations and leaked secrets for GitHub repositories and local directories, all
through one normalized view. It does not build its own security engine: Trivy and Gitleaks
are imported as Go libraries, so there is no Docker daemon, no Python and no external CLI.
Nothing leaves the machine except the calls listed under [Network calls](#network-calls).

![bastion: connect GitHub, add a repo, scan, read the report](docs/demo.gif)

📖 **Documentation:** see the [wiki](docs/wiki/Home.md) — getting started, CLI, CI, findings, security, troubleshooting.

## Status

**v0.1 in progress (Phase 1 — core MVP).** Working today: GitHub PAT connection (token in
the OS keyring), repo discovery and tarball fetch, scan jobs with live progress, Trivy
(vulnerabilities, licences, IaC) and Gitleaks (working-tree secrets) adapters, ignore with
reason, Security Reports, and `bastion scan` with JSON, table and SARIF output. Container
images, fix plans, SAST and MCP are later phases.

## Install

Homebrew (tap is `ozerozdas/homebrew-tap`; the cask installs the prebuilt binary):

```sh
brew install ozerozdas/tap/bastion
```

Script — detects macOS/Linux and amd64/arm64, downloads the latest release,
verifies its sha256 against `checksums.txt` and installs to `~/.local/bin`
(override with `BASTION_INSTALL_DIR`, pin with `BASTION_VERSION=v0.1.0`):

```sh
curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh
```

Read it first: [install.sh](install.sh) — it is ~110 lines and needs only
`curl`, `tar` and `sha256sum`/`shasum`.

Or from source: Go 1.27+, Node 24 (the web UI is embedded into the binary, so it
is built first).

```sh
git clone https://github.com/ozerozdas/bastion && cd bastion
make build        # → bin/bastion
./bin/bastion version
```

Prebuilt binaries are ~156 MiB; the
first scan additionally downloads a ~1.7 GB vulnerability DB into the cache directory.

## 5-minute quickstart

1. Run `./bin/bastion`. The server binds `127.0.0.1` on a random port, prints the URL and
   opens your browser. Use `bastion serve --port 8080 --no-browser` to control that.
2. **Connections** → add a GitHub token. It must be read-only: a fine-grained PAT with
   *Contents: read* and *Metadata: read*, or a classic PAT with the `repo` scope for
   private repositories. The token goes into the OS keychain and is never stored in the
   database or shown again.
3. **Projects** → **List repositories** → tick repositories → add them → **Scan**. Scans
   run locally, at most `--concurrency` (default 2) at a time; progress streams into the
   project row.
   No GitHub? Use **Add a local path** with an absolute directory instead.
4. **Security Reports** shows one project's latest findings, filterable, with the fixed
   version that closes each one. Hide a finding as *ignored*, *accepted risk* or *false
   positive*; a reason is required and the decision applies to later scans of that project.
5. **Scan History** lists past scans. Stuck setup? `bastion doctor` prints paths, versions,
   keyring availability and database health (`--json` for scripting).

## CLI

```
bastion [flags]                  # same as `bastion serve`
bastion serve   [--port N] [--no-browser] [--concurrency N]
bastion scan    --path DIR | --repo owner/name[@ref]
                [--format json|table|sarif] [--fail-on critical|high|medium|low]
                [--skip-dirs DIR]...  [--no-store]
bastion doctor  [--json]
bastion version
```

Root flags (apply to every subcommand): `--data-dir`, `--cache-dir`, `--log-format
text|json`, `--log-level debug|info|warn|error`.

```sh
# Scan a directory, human-readable
bastion scan --path . --format table

# Scan a GitHub repo's default branch (token from a saved connection or BASTION_GITHUB_TOKEN)
bastion scan --repo ozerozdas/bastion --format json

# CI: write SARIF, fail the build on critical findings
export BASTION_HMAC_KEY="$(openssl rand -base64 32)"
bastion scan --path . --no-store --skip-dirs testdata \
  --format sarif --fail-on critical > bastion.sarif
```

`--fail-on` exits **2** when an open finding is at or above the threshold, so CI can tell
"findings found" from "the scan broke" (exit 1). `--no-store` does not touch the database,
which is what a CI runner wants.

## Network calls

Nothing else is called. No telemetry, no update check, no analytics: Trivy runs with
`--disable-telemetry --skip-version-check`, and the core has no other HTTP client.

| Destination | When | Why |
|---|---|---|
| `mirror.gcr.io/aquasec/trivy-db`, `ghcr.io/aquasecurity/trivy-db` | First scan, then on DB refresh | Vulnerabilities, package advisories. ~1.7 GB on first download |
| `mirror.gcr.io/aquasec/trivy-java-db`, `ghcr.io/aquasecurity/trivy-java-db` | Scan containing Java artifacts | Java index DB, needed to map `.jar` files to artifacts |
| `mirror.gcr.io/aquasec/trivy-checks:2` | When misconfiguration scanning runs | IaC checks bundle, ~2.6 MB |
| `api.github.com` | Only on user action: test connection, discover repos, add asset, scan | `GET /user`, `GET /user/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/commits/{branch}`, `GET /repos/{owner}/{repo}/tarball/{sha}` |
| `codeload.github.com` | Redirect target of the tarball call | The repository archive itself |

The three Trivy registries are OCI pulls performed by Trivy's updater; they are cached
under `<cache>/trivy` and re-used by later scans. GitHub is never contacted in the
background, and request URLs are never logged (private-repo redirects carry a short-lived
token).

## Threat model

Bastion is a local tool protecting a local user; it assumes the machine and the user
account are trusted, not that the network is.

What it does:

- **Loopback only.** Binds `127.0.0.1`, random port unless `--port` is given. Every route,
  including the UI, is behind the session check.
- **Single-use startup token.** The URL carries `?t=<token>`; the server trades it for an
  `HttpOnly; SameSite=Strict` session cookie and answers with a page that refreshes to the
  same URL without the token (not a `303`: a redirect would keep the cross-site context of a
  link opened from another app, and the Strict cookie would not be sent), so it leaves the
  address bar and browser history immediately. A second use is
  rejected.
- **DNS-rebinding guard.** Requests whose `Host` header is not `127.0.0.1:<port>` or
  `localhost:<port>` get `421`.
- **CSRF.** Mutating `/api/*` requests require `X-Bastion: 1`. There is no CORS support, so
  another origin cannot add that header.
- **Response hardening.** `Content-Security-Policy: default-src 'self'`, `X-Frame-Options:
  DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **Credentials.** GitHub tokens live in the OS keyring, never in SQLite and never in logs
  or API responses (`BASTION_GITHUB_TOKEN` is a read-only fallback for headless use).
- **Secrets findings.** Gitleaks matches are stored redacted (first four characters plus
  `****`) with an `HMAC-SHA256` under a random 32-byte local key from the keyring
  (`BASTION_HMAC_KEY` overrides it). The raw secret is never persisted; the HMAC exists so
  the same secret can be recognised across scans without being recoverable.
- **Scanned content is data, never instructions.** File contents, package metadata and
  scanner descriptions are untrusted input; analyzers run with explicit size/time budgets
  (tarball capped at 512 MiB compressed, 2 GiB / 200k files extracted) and report partial
  coverage instead of failing silently.

What it does **not** protect against:

- Another process running as the same user. It can read the database, the cache and the
  session cookie, and can use the OS keyring on your behalf.
- A compromised machine: malware, a keylogger, or an attacker with your unlocked session.
- Anyone who can open the URL printed at startup before you do (it is a bearer token).
- Malicious scanned content beyond the budgets and path checks above — bastion is not a
  sandbox and Gitleaks/Trivy parse attacker-controlled files in-process.
- Network observers of your GitHub or registry traffic (ordinary TLS trust applies).

## Data and paths

Defaults are `flag > environment > platform default`:

| What | Default | Override |
|---|---|---|
| Data dir (SQLite `bastion.db`) | `<user config dir>/bastion` — `~/Library/Application Support/bastion` (macOS), `~/.config/bastion` (Linux) | `--data-dir`, `BASTION_DATA_DIR` |
| Cache dir | `<user cache dir>/bastion` — `~/Library/Caches/bastion` (macOS), `~/.cache/bastion` (Linux) | `--cache-dir`, `BASTION_CACHE_DIR` |
| Trivy DB and checks | `<cache>/trivy` | (cache dir) |
| Repo workspaces | `<cache>/workspaces`, deleted after each scan | (cache dir) |

The cache directory is the large artifact on disk, not the binary. Deleting it is safe; the
next scan re-downloads the DB.

## Development

```sh
make check   # gofmt, golangci-lint, tsc --noEmit, vite build, go test, go build
make gen     # sqlc + oapi-codegen + openapi-typescript (after changing SQL/queries/API)
make test    # go test ./...
```

Project management lives in `.pm/` (tasks in `.pm/tasks/`, decisions in `.pm/decisions/`,
the rulebook in `PROJECT_SPEC.md`).

## License

Apache-2.0. See [LICENSE](LICENSE). Compatible with Trivy (Apache-2.0) and Gitleaks (MIT).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).
