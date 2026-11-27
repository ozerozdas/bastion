# Roadmap

Each phase ends with a tagged release. Every item below is a GitHub issue under its
[milestone](https://github.com/ozerozdas/bastion/milestones); want to help? Start with a
[good first issue](https://github.com/ozerozdas/bastion/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

| Phase | Version | Focus | Status |
|---|---|---|---|
| 0 | — | Skeleton: Trivy + Gitleaks as libraries in one pure-Go binary | Done |
| 1 | v0.1 | Core MVP: GitHub, scans, reports, CLI with SARIF | Done (v0.1.0) |
| 2a | v0.2 | Diff & OSV | Done (v0.2.0) |
| 2b | v0.3 | Containers & links | Done (v0.3.0) |
| 3 | v0.4 | Actionable output | Done (v0.4.0) |
| 4 | v0.5 | AI & automation | Done (v0.5.0) |
| 5 | v0.6 | Continuous visibility | Done (v0.6.0) |
| 6 | v0.7 | Individual depth | [Planned](https://github.com/ozerozdas/bastion/milestone/10) |
| 7 | v0.8 | Team without a server | [Planned](https://github.com/ozerozdas/bastion/milestone/11) |
| 8 | v0.9 | Scope expansion | [Planned](https://github.com/ozerozdas/bastion/milestone/12) |
| — | later | Backlog | [Ideas](https://github.com/ozerozdas/bastion/milestone/6) |

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

## v0.6 — Continuous visibility

- Scheduled scans for one local user while `bastion serve` runs
- End-of-life runtime and OS findings (opt-in, outbound call clearly labelled)
- Suppression rules and view filters to cut finding noise; agents can propose noise via MCP
- A findings page per asset, and a Reports page

Git-history secret scanning moved to v0.7; shipped source maps stay in the backlog.

## v0.7 — Individual depth

Less noise and more coverage for one developer.

- OSSF malicious-packages feed as a second malware source (opt-in)
- `bastion report`: coverage, findings, decisions and policy in one snapshot
- Your own rule packs for Opengrep and IaC checks
- Opt-in full git-history secret scanning
- Verify a fix: rescan the upgrade PR branch and show what it closed
- MCP recipes for common agent workflows
- Spike: JS/TS reachability; design: an install-time guard against malicious packages

## v0.8 — Team without a server

Findings follow from the repository, so only decisions and policy need sharing. They live
in the repository under `.bastion/`, are reviewed in pull requests, and git history is the
audit trail.

- Export and import triage decisions and suppression rules
- Scans read `.bastion/` decisions, policy and rule packs from the scanned repository
- CI enforces the same policy and comments the finding diff on pull requests
- VEX export from triage decisions
- An audit trail view for every decision

## v0.9 — Scope expansion

Each item ships only with its rows in [Network Calls](Network-Calls.md); all of them are
read-only or opt-in.

- Kubernetes cluster scanning through your kubeconfig
- AWS misconfiguration checks on a connected account (CSPM-lite), after an ADR on how
- DAST-lite as an opt-in downloaded module, for hosts you add

## Later

Grype and Syft, multi-user server mode, binary hardening, deeper JS bundle inspection,
hosted LLM providers, code-level autofix for SAST and IaC findings. These are
[`needs-discussion`](https://github.com/ozerozdas/bastion/issues?q=is%3Aopen+label%3Aneeds-discussion) issues: comment
before building.

## Not planned

Hosted/SaaS mode, runtime protection (in-app firewall, bot blocking), pentesting,
monitoring while the app is closed (CI covers it from v0.8), writing our own
vulnerability matching.
