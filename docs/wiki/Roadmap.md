# Roadmap

Each phase ends with a tagged release. Every item below is a GitHub issue under its
[milestone](https://github.com/ozerozdas/bastion/milestones); want to help? Start with a
[good first issue](https://github.com/ozerozdas/bastion/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

| Phase | Version | Focus | Status |
|---|---|---|---|
| 0 | — | Skeleton: Trivy + Gitleaks as libraries in one pure-Go binary | Done |
| 1 | v0.1 | Core MVP: GitHub, scans, reports, CLI with SARIF | Done (v0.1.0) |
| 2a | v0.2 | Diff & OSV | [Planned](https://github.com/ozerozdas/bastion/milestone/1) |
| 2b | v0.3 | Containers & links | [Planned](https://github.com/ozerozdas/bastion/milestone/4) |
| 3 | v0.4 | Actionable output | [Planned](https://github.com/ozerozdas/bastion/milestone/2) |
| 4 | v0.5 | AI & automation | [Planned](https://github.com/ozerozdas/bastion/milestone/3) |
| 5 | later | Scale-out | [Ideas](https://github.com/ozerozdas/bastion/milestone/6) |

Patch releases (v0.1.x, v0.2.x, …) carry fixes and small chores only; see the open
patch milestone.

## v0.2 — Diff & OSV

- Scan diff in UI and API: new / fixed / persisting
- Per-severity counts in the scan list
- SBOM export (CycloneDX)
- OSV-Scanner: malicious-package detection, deduplicated with Trivy

## v0.3 — Containers & links

- AWS connection (profiles / SSO) and ECR image scanning, without a Docker daemon
- Optional local Docker image scanning
- Repo ↔ image links (manual, then from OCI labels)

## v0.4 — Actionable output

- **Fix plan:** "upgrade X to Y → closes N findings (C critical, H high)"
- Prioritization: severity × fix available × EPSS × deployed
- Outdated packages (opt-in, outbound call clearly labelled)
- Bulk ignore, expiry dates for accepted risk
- Go reachability via govulncheck
- SAST as an opt-in downloaded module (Opengrep)
- Licence allow/deny policies

## v0.5 — AI & automation

- MCP server (`bastion mcp`) so AI agents can query findings and fix plans
- Dependency-upgrade PRs on GitHub (you confirm each one)
- Slack / email notifications on new critical/high
- Optional local LLM (Ollama on localhost only), off by default
- Official GitHub Action with SARIF upload

## Later

Grype and Syft, git-history secret scanning, server mode with scheduled scans, binary
hardening, JS bundle inspection, reachability beyond Go. These are
[`needs-discussion`](https://github.com/ozerozdas/bastion/issues?q=is%3Aopen+label%3Aneeds-discussion) issues: comment
before building.

## Not planned

Multi-user/SaaS mode in v1, monitoring while the app is closed, DAST, cloud posture
management, writing our own vulnerability matching.
