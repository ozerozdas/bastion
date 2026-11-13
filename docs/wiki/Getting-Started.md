# Getting Started

Goal: your first security report in about five minutes.

## 1. Install

**Homebrew** (macOS / Linux):

```sh
brew install ozerozdas/tap/bastion
```

**Install script** — detects OS/arch, downloads the latest release, verifies its sha256
against `checksums.txt`, installs to `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh
```

| Variable | Effect |
|---|---|
| `BASTION_INSTALL_DIR` | Install somewhere other than `~/.local/bin` |
| `BASTION_VERSION=v0.1.0` | Pin a specific release |

The script is ~110 lines and needs only `curl`, `tar` and `sha256sum`/`shasum` —
[read it](../../install.sh) before piping it to `sh`.

**From source** (Go 1.27+, Node 24):

```sh
git clone https://github.com/ozerozdas/bastion && cd bastion
make build            # → bin/bastion (builds the web UI first, then embeds it)
./bin/bastion version
```

> **Disk space:** the binary is ~156 MiB. The **first scan** downloads a ~1.7 GB
> vulnerability database into the [cache directory](Configuration-and-Paths.md).

## 2. Start it

```sh
bastion
```

The server binds `127.0.0.1` on a random port, prints the URL and opens your browser.
To pick the port or skip the browser:

```sh
bastion serve --port 8080 --no-browser
```

The printed URL contains a one-time token — open it yourself in that case. See
[Security and Privacy](Security-and-Privacy.md#the-startup-url) for why.

## 3. Connect GitHub (optional)

**Connections → add a GitHub token.** Use a **read-only** token:

| Token type | Permissions |
|---|---|
| Fine-grained PAT (recommended) | *Contents: read*, *Metadata: read* |
| Classic PAT | `repo` scope (needed only for private repositories) |

The token goes into the OS keychain. It is never written to the database, logs or API
responses, and is never shown again.

No GitHub? Skip this step and use **Add a local path** in the next one.

## 4. Add projects and scan

**Projects → List repositories** → tick the ones you want → add them → **Scan**.
Or **Add a local path** with an absolute directory.

Progress streams live into the project row. At most `--concurrency` scans (default 2) run
at the same time.

## 5. Read the findings

**Findings** lists the latest findings across all projects, filterable by project, type,
severity and status, with the fixed version that closes each vulnerability. Continue with
[Using the Web UI](Using-the-Web-UI.md) and [Findings](Findings.md).

Something off? Run `bastion doctor` — see [Troubleshooting](Troubleshooting.md).
