# Security and Privacy

Bastion is a local tool protecting a local user. It trusts your machine and your user
account; it does not trust the network or the code it scans.

## Network calls

Nothing else is called. No telemetry, no analytics, and no update check unless you turn
it on.

| Destination | When | Why |
|---|---|---|
| `mirror.gcr.io/aquasec/trivy-db`, `ghcr.io/aquasecurity/trivy-db` | **Download** in the sidebar, or the first scan that needs it; then on DB refresh | Vulnerability advisories (~1.7 GB first time) |
| `mirror.gcr.io/aquasec/trivy-java-db`, `ghcr.io/aquasecurity/trivy-java-db` | Scans with Java artifacts | Maps `.jar` files to artifacts |
| `mirror.gcr.io/aquasec/trivy-checks:2` | Misconfiguration scanning | IaC checks bundle (~2.6 MB) |
| `api.github.com` | **Only on your action**: test connection, list repos, add, scan | Identity, repo list, commit SHA, tarball |
| `codeload.github.com` | Redirect of the tarball call | The repository archive |
| `github.com/ozerozdas/bastion/releases/latest` | At most once a day, only after you turn the release check on in the UI | Newest release tag. Sends your IP and `User-Agent: bastion/<version>`; the redirect is not followed |

GitHub is contacted in the background only by the daily release check; every scan,
discovery and download call happens on your action. Opening the UI downloads nothing: the
vulnerability DB arrives when you press **Download** in the sidebar or when a scan needs
it. Request URLs are never logged (private-repo redirects carry a short-lived token). The
release check is disabled by `BASTION_NO_UPDATE_CHECK=1`, in CI, and in `dev` builds,
whatever the stored choice.

## The local server

| Protection | What it does |
|---|---|
| Loopback only | Binds `127.0.0.1`; random port unless `--port` |
| Session check | Every route, UI included, needs the session cookie |
| DNS-rebinding guard | `Host` must be `127.0.0.1:<port>` or `localhost:<port>`, else `421` |
| CSRF | Mutating `/api/*` calls need the `X-Bastion: 1` header; no CORS, so other sites can't send it |
| Response headers | `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` |

### The startup URL

The URL bastion prints looks like `http://127.0.0.1:PORT/?t=TOKEN`. The token is
**single-use**: the first visit trades it for an `HttpOnly; SameSite=Strict` cookie, and
the page reloads itself without the token so it leaves the address bar and history. A
second visit with the same token is rejected.

Treat the URL as a password until you've opened it.

## Data at rest

- **Tokens** — OS keyring only; never in SQLite, logs or API responses.
- **Secrets found in code** — redacted plus HMAC, never the raw value
  ([details](Findings.md#secrets)).
- **Scanned content** is untrusted input. Downloads are capped (512 MiB compressed tarball,
  2 GiB / 200k files extracted) and partial coverage is reported, not hidden.

## What bastion does *not* protect against

- Another process running as your user — it can read the database, cache and cookie, and
  use your keyring.
- A compromised machine (malware, keylogger, an unlocked session).
- Someone who opens the startup URL before you do.
- Malicious scanned content beyond the limits above. Bastion is not a sandbox; Trivy and
  Gitleaks parse untrusted files in-process.
- Network observers of your GitHub or registry traffic beyond normal TLS.
