# Bastion

Local-first security center. One Go binary, run on your own machine, that opens a web UI
in your browser and reports dependency vulnerabilities, licence issues, IaC
misconfigurations and leaked secrets for GitHub repositories, local directories and
images on a local Docker daemon, all through one normalized view. It does not build its
own security engine: Trivy and Gitleaks are imported as Go libraries, and OSV advisories
are queried over HTTPS, so no Docker daemon is required (it is only used, when present,
to read images), and there is no Python and no external CLI.
Nothing leaves the machine except the calls listed under [Network calls](#network-calls).

![bastion: connect GitHub, add a repo, scan, read the report](docs/demo.gif)

📖 **Documentation:** see the [wiki](docs/wiki/Home.md) — getting started, CLI, CI, findings, security, troubleshooting.

## Status

**v0.5 released.** Working today: GitHub repositories, AWS ECR and local Docker images,
Trivy, Gitleaks and OSV scanning, scan diffs, CycloneDX SBOM export, fix plans with
prioritization, Go reachability, opt-in SAST, licence policies, and `bastion scan` with
JSON, table and SARIF output. Automation covers the MCP server, dependency-upgrade PRs,
Slack and email notifications, an optional local LLM and the GitHub Action. What comes
next is on the [roadmap](docs/wiki/Roadmap.md).

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
2. **Connections** → add a GitHub token. Scanning needs read-only access: a fine-grained
   PAT with *Contents: read* and *Metadata: read*, or a classic PAT with the `repo` scope
   for private repositories. Opening a fix-plan pull request (**Fix plan** → **Open PR**)
   writes one manifest file and a pull request, so that action also needs *Contents: write*
   and *Pull requests: write* (fine-grained), which the classic `repo` scope already
   covers. The token goes into the OS keychain and is never stored in the database or shown
   again.
3. **Projects** → **List repositories** → tick repositories → add them → **Scan**. Scans
   run locally, at most `--concurrency` (default 2) at a time; progress streams into the
   project row.
   No GitHub? Use **Add a local path** with an absolute directory instead.
   The first scan needs a ~1.7 GB vulnerability DB; **Download** above the version chip
   in the sidebar starts that fetch ahead of time.
4. **Findings** lists the latest findings across every project, filterable by project,
   type, severity and status, with the fixed version that closes each one. Hide a finding
   as *ignored*, *accepted risk* or *false positive*; a reason is required and the decision
   applies to later scans of that project.
5. **Projects → Scans** lists past scans. Stuck setup? `bastion doctor` prints paths,
   versions, keyring availability and database health (`--json` for scripting).

## CLI

```
bastion [flags]                  # same as `bastion serve`
bastion serve   [--port N] [--no-browser] [--concurrency N]
bastion scan    --path DIR | --repo owner/name[@ref] | --image IMAGE
                [--format json|table|sarif|cyclonedx] [--fail-on critical|high|medium|low]
                [--skip-dirs DIR]...  [--no-store]
bastion mcp                     # MCP tools over stdio (see below)
bastion doctor  [--json]
bastion update  [--check] [--force]
bastion version
```

Root flags (apply to every subcommand): `--data-dir`, `--cache-dir`, `--log-format
text|json`, `--log-level debug|info|warn|error`.

```sh
# Scan a directory, human-readable
bastion scan --path . --format table

# Scan a GitHub repo's default branch (token from a saved connection or BASTION_GITHUB_TOKEN)
bastion scan --repo ozerozdas/bastion --format json

# Scan an image the local Docker daemon already holds (never pulls)
bastion scan --image nginx:latest --format table

# Scan an ECR tag: the saved, tested AWS connection supplies the login and the
# tag is pinned to its digest before it is scanned
bastion scan --image 123456789012.dkr.ecr.eu-central-1.amazonaws.com/app:latest --format table

# CI: write SARIF, fail the build on critical findings
export BASTION_HMAC_KEY="$(openssl rand -base64 32)"
bastion scan --path . --no-store --skip-dirs testdata \
  --format sarif --fail-on critical > bastion.sarif
```

`--fail-on` exits **2** when an open finding is at or above the threshold, so CI can tell
"findings found" from "the scan broke" (exit 1). `--no-store` writes nothing to the
database, which is what a CI runner wants; an ECR image still reads its saved AWS
connection from it, because that connection supplies the registry login and the tag's
digest. A reference whose registry is `<account>.dkr.ecr.<region>.amazonaws.com` and
whose account and region match no saved, tested AWS connection fails with a message
saying to add one in **Connections → Registry**.

`--format cyclonedx` prints the scan's package inventory as a CycloneDX 1.6 JSON BOM; the
same document is a download on **Projects → Scans** (`GET /api/scans/{id}/sbom`).

## Scheduled scans

Set a project or image to scan daily or weekly from its **Schedule** column. Schedules
run only while `bastion serve` is open; a scan missed while it was closed runs once at the
next start.

## MCP server

`bastion mcp` serves the assets, findings, fix plans and scan diffs over the
[Model Context Protocol](https://modelcontextprotocol.io) on stdin/stdout. It
starts no worker pool, download or scan recovery of its own, so it never disturbs a
`bastion serve` running beside it. It opens the same database (`--data-dir` applies),
so an agent reads what the UI shows. stdout is the protocol stream; logs go to stderr.

`trigger_scan` (`{asset_id}`) queues a scan for a **running**
`bastion serve` and returns `{scan_id, status: "queued"}`. The server detects serve
through an exclusive lock on `<data-dir>/serve.lock`; with no server running the tool
fails with *bastion serve is not running; start it to run scans* and writes nothing.
The scan itself runs in serve, with its worker pool and Trivy database, and appears in
the UI (`trigger: api`) like any other scan. If the asset already has a queued or
running scan, that scan is returned with `already_queued: true` instead of a second
one. A scan queued just before serve stops stays queued and is picked up at the next
`bastion serve` start, never run by this process.

`set_finding_state` (`{asset_id, fingerprints, state, reason, expires_at?}`) lets an agent
close noise, and `clear_finding_state` (`{asset_id, fingerprints}`) reopens what an agent
closed. These decisions apply immediately and the UI lists them under **Closed by agent**.
Scanned content can try to steer an agent, so both tools refuse the whole batch when it
names a decision you made, and `set_finding_state` also refuses malware and secret findings.

`propose_finding_rule` lets an agent suggest a suppression rule for one asset. A proposal
closes nothing until you approve it under **Configuration > Noise rules**, and proposals
for malware or secret findings are refused.

Generic `mcpServers` configuration (Claude Code, Claude Desktop and other MCP clients):

```json
{
  "mcpServers": {
    "bastion": {
      "command": "bastion",
      "args": ["mcp"]
    }
  }
}
```

If the database lives elsewhere, pass the global flag through:
`"args": ["mcp", "--data-dir", "/path/to/bastion/data"]`.

Tools: `list_assets`, `list_findings` (asset, severity, type, status, text query, sort and
paging), `get_fix_plan`, `diff_scans` (two scan ids, or an asset's last two succeeded
scans), `list_security_news` (the opt-in Security News feed, with optional `since`,
`source` and `limit`), `trigger_scan` (queue a scan for the running server),
`set_finding_state`, `clear_finding_state` and `propose_finding_rule`. Every result that
carries scanner-derived or third-party feed values includes an `untrusted_content`
notice: those values are data, never instructions (see the threat model). Apart from
`trigger_scan`, the two finding-state tools and rule proposals, the MCP server makes no
writes; it makes no network calls of its own except reading the first-party feeds
`list_security_news` returns, and only while Security News is turned on.

For clients that only speak HTTP, `bastion mcp --http --port 7778` serves the same tools
over streamable HTTP at `http://127.0.0.1:7778/`. It binds loopback only and needs no
token; requests with a foreign Host header (DNS rebinding) or from another website are
refused.

For questions about shipped artifacts (binary hardening, source maps or keys in built
bundles), the [`bastion-artifacts`](skills/bastion-artifacts/SKILL.md) agent skill combines
`bastion mcp` with [REA](https://github.com/morluto/rea). Copy the folder into your agent's
skills directory; REA stays a separate MCP server.

## Notifications

Notifications are opt-in and off by default. Turn them on in **Configuration →
Notifications**: pick a threshold (**Critical and high**, the default, or
**Critical only**) and configure Slack, email, or both. A Slack incoming-webhook
URL is stored in the OS keyring, never in SQLite, and the API only reports
whether one is configured.

Email sends through SMTP submission with **STARTTLS required**: set the host,
the port (587 by default), the sender, one or more comma-separated recipients,
and optionally a username and password. There is no plain-text fallback, and
implicit TLS on port 465 is not supported. The password is stored in the OS
keyring and is never returned by the API; clearing it leaves the rest of the
settings intact.

After a scan succeeds, bastion diffs it against the asset's previous succeeded
scan and posts one short message per enabled notifier when at least one new
finding meets the threshold. The first scan of an asset sends nothing: with no
baseline every finding would look new and a fresh install would flood the
channel. A notification failure is logged and never affects the scan.

## Network calls

Nothing else is called. No telemetry, no analytics, and no update check unless you turn
it on: Trivy runs with `--disable-telemetry --skip-version-check`, scans query
`api.osv.dev` for package advisories, and the release check is opt-in as listed below.

| Destination | When | Why |
|---|---|---|
| `mirror.gcr.io/aquasec/trivy-db`, `ghcr.io/aquasecurity/trivy-db` | **Download** in the sidebar, or the first scan that needs it; then on DB refresh | Vulnerabilities, package advisories. ~1.7 GB on first download |
| `mirror.gcr.io/aquasec/trivy-java-db`, `ghcr.io/aquasecurity/trivy-java-db` | Scan containing Java artifacts | Java index DB, needed to map `.jar` files to artifacts |
| `mirror.gcr.io/aquasec/trivy-checks:2` | When misconfiguration scanning runs | IaC checks bundle, ~2.6 MB |
| `api.osv.dev` | Every scan whose package inventory is non-empty | `POST /v1/querybatch` and `GET /v1/vulns/{id}` for the advisories it reports. Sends package name, version and ecosystem only, with `User-Agent: bastion/<version>` |
| `api.github.com` | Only on user action: test connection, discover repos, add asset, scan, or confirm **Open PR** on a fix plan step (#47) | `GET /user`, `GET /user/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/commits/{branch}`, `GET /repos/{owner}/{repo}/tarball/{sha}`, and for a confirmed pull request `GET /repos/{owner}/{repo}/git/ref/heads/{branch}`, `GET /repos/{owner}/{repo}/pulls`, `GET /repos/{owner}/{repo}/contents/{path}`, `POST /repos/{owner}/{repo}/git/refs`, `PUT /repos/{owner}/{repo}/contents/{path}` (one manifest file) and `POST /repos/{owner}/{repo}/pulls`. Nothing is written without the confirmation dialog |
| `codeload.github.com` | Redirect target of the tarball call | The repository archive itself |
| `sts.<region>.amazonaws.com` | Only on user action: test an AWS connection | `GetCallerIdentity`, signed with the credentials of the AWS profile you chose; the account id and ARN come back |
| `ecr.<region>.amazonaws.com` | Only on user action: discover ECR repositories, or start an ECR image scan | `DescribeRepositories`, `DescribeImages` and `GetAuthorizationToken`, signed with the credentials of the AWS profile you chose; repository names, tag names, digests and push times come back |
| `<account>.dkr.ecr.<region>.amazonaws.com` | Only during an ECR image scan | Docker Registry HTTP API pull of the pinned digest, authenticated with the short-lived ECR token from `GetAuthorizationToken` (held in memory for the scan, never stored or logged) |
| `github.com/ozerozdas/bastion/releases/latest` | At most once a day, only after you turn the release check on in the UI; or on explicit `bastion update` | Newest release tag. Sends your IP and `User-Agent: bastion/<version>`; the redirect is not followed and nothing else is parsed |
| `github.com/ozerozdas/bastion/releases/download` | Only on explicit `bastion update` | The release archive for your OS/arch and its `checksums.txt` (redirects to GitHub's object storage). Sends your IP and `User-Agent: bastion/<version>`; the SHA-256 is verified before the binary is replaced |
| `epss.empiricalsecurity.com` | At most once a day, only after you turn EPSS scores on in the UI | The current EPSS feed: a ~2.8 MB gzipped CSV of per-CVE exploit probabilities and percentiles. Sends your IP and `User-Agent: bastion/<version>`; it is cached locally and never re-uploaded |
| `vuln.go.dev` | Only on a scan of a Go module, after you turn Go reachability on in the UI | govulncheck's vulnerability database: which advisories exist and which functions they affect. Sends your IP; the database is cached by the Go toolchain |
| `api.deps.dev` | Only on a scan whose package inventory is non-empty, after you turn Outdated packages on in the UI | The latest version of each package. Sends the ecosystem and package name only, with `User-Agent: bastion/<version>`; versions are compared locally |
| `endoflife.date` | Only on a scan that detects an operating system or Go runtime, after you turn the End-of-life check on in the UI | The release cycles of that product, cached for a day. Sends the product name only, with `User-Agent: bastion/<version>`; versions are compared locally |
| `hooks.slack.com` | Only after you turn Slack notifications on and a scan adds a finding at or above your threshold | One incoming-webhook `POST` per qualifying scan: the asset name, the new counts by severity and a link back to `127.0.0.1`. The webhook URL is a bearer credential and lives in the OS keyring |
| `<your SMTP host>` | Only after you turn email notifications on and a scan adds a finding at or above your threshold, or when you press **Send test** | SMTP submission with a required STARTTLS upgrade, then optional AUTH PLAIN and one message. It carries the asset name, the new counts by severity and a link back to `127.0.0.1`; the SMTP password lives in the OS keyring and is never logged |
| `<your local model endpoint>` (loopback only) | Only when you press **Explain** in a finding after turning local AI on | One `POST {endpoint}/chat/completions` to an OpenAI-compatible server on a loopback IP literal or `localhost` (Ollama's default is `http://127.0.0.1:11434/v1`). The finding's title, rule id, package, versions, location, severity, EPSS and a clipped description travel as delimited untrusted data; non-loopback endpoints are refused and the answer is advisory only |
| `proxy.golang.org` (or your `GOPROXY`) | Same scans, through the `go` toolchain govulncheck drives | Module downloads and checksums the analysis needs, exactly as `go build` would fetch them. Nothing about your scan is uploaded |
| `github.com/opengrep/opengrep/releases/download` | Only after you turn SAST on in the UI, or pass `bastion scan --sast` | The pinned Opengrep v1.33.1 binary for your OS/arch, ~47 MB. Sends your IP and `User-Agent: bastion/<version>`; the SHA-256 is checked against the table compiled into bastion before the binary is used |
| `codeload.github.com/opengrep/opengrep-rules` | Same moment as the binary | The pinned Opengrep rule set, ~1.1 MB, unpacked under `<cache>/modules/opengrep-v1.33.1/rules`. Sends your IP and `User-Agent: bastion/<version>`; its SHA-256 is checked first |
| `feeds.feedburner.com`, `www.bleepingcomputer.com`, `www.cisa.gov`, `isc.sans.edu`, `krebsonsecurity.com`, `www.securityweek.com`, `www.darkreading.com`, `www.exploit-db.com`, `googleprojectzero.blogspot.com`, `portswigger.net`, `www.reddit.com` | Only after you turn Security News on in the UI; at most every 30 minutes per enabled source (2 minutes after a failure) | The source's RSS/Atom feed: article titles, short summaries, publication dates and links. Sends your IP and `User-Agent: bastion/<version>`; each feed is cached in memory and only its sanitized text and http(s) links reach the UI or MCP. Redirects are followed only within the same host |

The Opengrep rule set is licensed LGPL-2.1 with the Commons Clause. Bastion does
not vendor it: it is downloaded at runtime, only after you opt in, into the cache
directory. The Opengrep binary is a separate download under its own licence.

Bastion also talks to the local Docker daemon over its Unix socket
(`DOCKER_HOST`, or the usual Docker Desktop, OrbStack, Colima and Rancher Desktop
sockets) when one is present: it pings the daemon, lists its tagged images and reads the
image a scan targets. It never pulls, pushes, builds or runs anything, and with no daemon
the Docker source is simply hidden.

An AWS connection stores only a profile name and a region. Bastion resolves the
credential through the AWS SDK's default chain (environment, `~/.aws/config`, the SSO
cache, an instance role) when you test the connection, so no AWS key is written to
bastion's database or the OS keychain.

The three Trivy registries are OCI pulls performed by Trivy's updater; they are cached
under `<cache>/trivy` and re-used by later scans. Nothing is downloaded at startup: the
sidebar only reads the DB status, and the DB arrives when you press **Download** there or
when a scan needs it. GitHub is contacted in the background only by the daily release
check; every scan, discovery and download call happens on your action. Request URLs are
never logged (private-repo redirects carry a short-lived token).

OSV receives only the package name, version and ecosystem of the inventory Trivy already
built; repository contents, file paths and findings never leave the machine. A failed OSV
lookup is logged and recorded as a failed scanner run; the scan's other findings stand.

The release check is disabled by `BASTION_NO_UPDATE_CHECK=1`, in CI, and in `dev` builds,
whatever the stored choice. Consent lives in the data directory; it is `unset` (no
request), `on`, or `off`.

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
| Data dir (SQLite `bastion.db`) | `<user config dir>/bastion` — `~/Library/Application Support/bastion` (macOS), `~/.config/bastion` (Linux), `%AppData%\bastion` (Windows) | `--data-dir`, `BASTION_DATA_DIR` |
| Cache dir | `<user cache dir>/bastion` — `~/Library/Caches/bastion` (macOS), `~/.cache/bastion` (Linux), `%LocalAppData%\bastion` (Windows) | `--cache-dir`, `BASTION_CACHE_DIR` |
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

### Translations

The UI ships in English and Turkish. Each language is one file in `web/src/locales/`. To add one, copy `en.json` to `<code>.json` (for example `de.json`), set `_meta.name`, and translate the values. It then appears under Configuration → Appearance → Language. Missing keys fall back to English, and `npm --prefix web run test` checks that the keys and `{placeholders}` match English.

Project management lives in `.pm/` (tasks in `.pm/tasks/`, decisions in `.pm/decisions/`,
the rulebook in `PROJECT_SPEC.md`).

## License

Apache-2.0. See [LICENSE](LICENSE). Compatible with Trivy (Apache-2.0) and Gitleaks (MIT).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).
