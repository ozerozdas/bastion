# Bastion

Local-first security center. One Go binary that runs on your machine, opens a web UI in
your browser and reports dependency vulnerabilities, licence issues, IaC
misconfigurations and leaked secrets in one normalized view. Trivy and Gitleaks are
embedded as Go libraries and OSV is queried over HTTPS, so there is no Python, no external
CLI and no Docker requirement. Nothing leaves the machine except the
[documented network calls](docs/wiki/Network-Calls.md).

[![Watch the Bastion trailer](https://img.youtube.com/vi/Mj73WNpVvPo/maxresdefault.jpg)](https://youtu.be/Mj73WNpVvPo)

▶️ **[Watch the trailer](https://youtu.be/Mj73WNpVvPo)** · 📖 **[Documentation](docs/wiki/Home.md)**

## What it does

- **Scans** GitHub repositories, local directories, local Docker images and AWS ECR images.
- **Finds** vulnerabilities (Trivy + OSV), leaked secrets (Gitleaks), IaC misconfigurations,
  licence issues, and optionally SAST (Opengrep), Go reachability, outdated and end-of-life packages.
- **Triages**: one findings view with filters, EPSS scores, scan diffs and ignore / accepted-risk
  / false-positive decisions that persist across scans.
- **Fixes**: prioritized fix plans, and one-click dependency-upgrade pull requests.
- **Exports** JSON, table, SARIF and CycloneDX SBOM; fails CI builds with `--fail-on`.
- **Automates**: scheduled scans, Slack / email notifications, a GitHub Action, an
  [MCP server](docs/wiki/MCP-Server.md) for AI agents and an optional local LLM to explain findings.
- **Stays local**: loopback-only server, credentials in the OS keyring, no telemetry.

## Install

```sh
# Homebrew
brew install ozerozdas/tap/bastion

# or script (macOS/Linux, verifies sha256, installs to ~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh
```

From source (Go 1.27+, Node 24): `git clone https://github.com/ozerozdas/bastion && cd bastion && make build`.

The first scan downloads a ~1.7 GB vulnerability database into the cache directory.

## Quickstart

1. Run `bastion`. It binds `127.0.0.1` on a random port and opens your browser.
2. **Connections** → add a GitHub token (read-only is enough for scanning), or skip GitHub and
   use **Add a local path**.
3. **Projects** → add repositories → **Scan**.
4. **Findings** shows the results across all projects.

From the terminal or CI:

```sh
bastion scan --path . --format table
bastion scan --path . --no-store --format sarif --fail-on critical > bastion.sarif
```

Stuck? `bastion doctor` prints paths, versions and health checks.

## Learn more

| Topic | Page |
|---|---|
| Install and first scan in detail | [Getting Started](docs/wiki/Getting-Started.md) |
| Web UI walkthrough | [Using the Web UI](docs/wiki/Using-the-Web-UI.md) |
| All commands and flags | [CLI Reference](docs/wiki/CLI-Reference.md) |
| GitHub Action and SARIF | [CI Integration](docs/wiki/CI-Integration.md) |
| MCP server for AI agents | [MCP Server](docs/wiki/MCP-Server.md) |
| Notifications and scheduled scans | [Notifications](docs/wiki/Notifications.md) |
| Network calls and threat model | [Network Calls](docs/wiki/Network-Calls.md) · [Security and Privacy](docs/wiki/Security-and-Privacy.md) |
| Data directories and env vars | [Configuration and Paths](docs/wiki/Configuration-and-Paths.md) |
| Building, testing, translations | [Development](docs/wiki/Development.md) |
| What's next | [Roadmap](docs/wiki/Roadmap.md) |

## License

Apache-2.0, see [LICENSE](LICENSE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
Report vulnerabilities privately per [SECURITY.md](SECURITY.md).
