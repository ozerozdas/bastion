# Roadmap

Each phase ends with a tagged release.

| Phase | Version | Focus | Status |
|---|---|---|---|
| 0 | — | Skeleton: Trivy + Gitleaks as libraries in one pure-Go binary | Done |
| 1 | v0.1 | Core MVP: GitHub, scans, reports, CLI with SARIF | **In progress** |
| 2 | v0.2 | Containers & diff | Planned |
| 3 | v0.3 | Actionable output | Planned |
| 4 | v0.4 | AI & automation | Planned |
| 5 | later | Scale-out | Ideas |

## v0.2 — Containers & diff

- AWS connection (profiles / SSO) and ECR image scanning, without a Docker daemon
- Optional local Docker image scanning
- Scan diff in UI and API: new / fixed / persisting
- Repo ↔ image links (manual, then from OCI labels)
- SBOM export (CycloneDX)
- OSV-Scanner: malicious-package detection

## v0.3 — Actionable output

- **Fix plan:** "upgrade X to Y → closes N findings (C critical, H high)"
- Prioritization: severity × fix available × EPSS × deployed
- Outdated packages (opt-in, outbound call clearly labelled)
- Bulk ignore, expiry dates for accepted risk
- Go reachability via govulncheck
- SAST as an opt-in downloaded module (Opengrep)
- Licence allow/deny policies

## v0.4 — AI & automation

- MCP server (`bastion mcp`) so AI agents can query findings and fix plans
- Dependency-upgrade PRs on GitHub (you confirm each one)
- Slack / email notifications on new critical/high
- Optional local LLM (Ollama on localhost only), off by default
- Official GitHub Action with SARIF upload

## Later

Grype and Syft, git-history secret scanning, server mode with scheduled scans.

## Not planned

Multi-user/SaaS mode in v1, monitoring while the app is closed, DAST, cloud posture
management, writing our own vulnerability matching.
