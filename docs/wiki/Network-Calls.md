# Network Calls and Threat Model

Nothing else is called. No telemetry, no analytics, and no update check unless you turn
it on: Trivy runs with `--disable-telemetry --skip-version-check`, scans query
`api.osv.dev` for package advisories, and the release check is opt-in as listed below.

| Destination | When | Why |
|---|---|---|
| `mirror.gcr.io/aquasec/trivy-db`, `ghcr.io/aquasecurity/trivy-db` | **Download** in the sidebar, or the first scan that needs it; then on DB refresh | Vulnerabilities, package advisories. ~1.7 GB on first download |
| `mirror.gcr.io/aquasec/trivy-java-db`, `ghcr.io/aquasecurity/trivy-java-db` | Scan containing Java artifacts | Java index DB, needed to map `.jar` files to artifacts |
| `mirror.gcr.io/aquasec/trivy-checks:2` | When misconfiguration scanning runs | IaC checks bundle, ~2.6 MB |
| `api.osv.dev` | Every scan whose package inventory is non-empty | `POST /v1/querybatch` and `GET /v1/vulns/{id}` for the advisories it reports. Sends package name, version and ecosystem only, with `User-Agent: bastion/<version>` |
| `api.github.com` | Only on user action: test connection, discover repos, add asset, scan, or confirm **Open PR** on a fix plan step  | `GET /user`, `GET /user/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/commits/{branch}`, `GET /repos/{owner}/{repo}/tarball/{sha}`, and for a confirmed pull request `GET /repos/{owner}/{repo}/git/ref/heads/{branch}`, `GET /repos/{owner}/{repo}/pulls`, `GET /repos/{owner}/{repo}/contents/{path}`, `POST /repos/{owner}/{repo}/git/refs`, `PUT /repos/{owner}/{repo}/contents/{path}` (one manifest file) and `POST /repos/{owner}/{repo}/pulls`. Nothing is written without the confirmation dialog |
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
