# Bastion Wiki

Bastion is a **local-first security center**: one Go binary that runs on your machine,
opens a web UI in your browser and reports, for GitHub repositories and local directories:

- dependency **vulnerabilities**,
- **licence** issues,
- **IaC misconfigurations** (Dockerfile, Terraform, Kubernetes, …),
- leaked **secrets** in the working tree.

Trivy and Gitleaks are compiled in as Go libraries; OSV advisories are queried over
HTTPS — no Docker daemon, no Python, no external CLI. No telemetry; the only network calls
are listed in [Security and Privacy](Security-and-Privacy.md#network-calls).

> **Status:** v0.1 (Phase 1 — core MVP). Container images, fix plans, SAST and MCP come in
> later phases — see [Roadmap](Roadmap.md).

## Start here

| I want to… | Read |
|---|---|
| Install bastion and get my first report | [Getting Started](Getting-Started.md) |
| Understand the sections of the UI | [Using the Web UI](Using-the-Web-UI.md) |
| Scan from the terminal or in CI | [CLI Reference](CLI-Reference.md) · [CI Integration](CI-Integration.md) |
| Understand what a finding is and how ignoring works | [Findings](Findings.md) |
| Know what bastion stores, where, and what it sends | [Configuration and Paths](Configuration-and-Paths.md) · [Security and Privacy](Security-and-Privacy.md) |
| Fix a problem | [Troubleshooting](Troubleshooting.md) |
| Hack on bastion | [Architecture](Architecture.md) · [Development](Development.md) |

## Bastion in one picture

```
 you ──▶ bastion (one binary, 127.0.0.1 only)
           ├── web UI + API          (browser, session cookie)
           ├── sources               GitHub tarball │ local path
           ├── scanners              Trivy │ Gitleaks │ OSV API   (in-process)
           ├── findings              normalize → fingerprint → store
           └── SQLite + cache        your data dir / cache dir
```
