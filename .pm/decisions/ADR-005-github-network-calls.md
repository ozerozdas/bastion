# ADR-005: GitHub API and tarball downloads (Phase 1 outbound calls)

- Status: proposed (needs Özer's approval, §11.3.5)
- Date: 2026-11-11
- Task: BST-015; used by BST-019, BST-020, BST-021, BST-031
- Spec refs: §8 Phase 1, §9.6 (new outbound calls need an ADR), §4.3

## Context
Phase 1 scans GitHub repositories. Today bastion's only outbound call is the
Trivy vulnerability/Java DB download (ADR-001). Connecting GitHub adds calls
that carry a user credential, so they must be explicit, minimal, and listed in
the README "Network calls" section.

## Decision
Bastion calls GitHub **only on user action** (add/test connection, discover,
add asset, scan). Never in the background, never on startup.

Host `api.github.com`, `Authorization: Bearer <PAT>`, `X-GitHub-Api-Version: 2022-11-28`:

| Call | Why |
|---|---|
| `GET /user` | Test a connection; show the identity (login) |
| `GET /user/repos?per_page=100&sort=pushed` (paginated via `Link`) | Discover repos to add |
| `GET /repos/{owner}/{repo}` | Default branch, private flag when adding an asset |
| `GET /repos/{owner}/{repo}/commits/{branch}` with `Accept: application/vnd.github.sha` | Resolve the branch to a SHA before fetching |
| `GET /repos/{owner}/{repo}/tarball/{sha}` | Download the source; 302 to `codeload.github.com` |

Rules:
- **Token:** classic or fine-grained PAT, read-only (fine-grained: *Contents: read*,
  *Metadata: read*). Stored in the keyring (env fallback `BASTION_GITHUB_TOKEN`),
  never in SQLite, never logged or returned by the API.
- **Redirects:** Go's `http.Client` drops `Authorization` when a redirect leaves
  `api.github.com`. Codeload redirect URLs for private repos carry a short-lived
  `token=` query parameter, so **request URLs are never logged**; only
  `owner/repo@sha` is.
- **Budgets:** tarball download capped (default 512 MiB compressed, 2 GiB / 200k
  files extracted), honours context cancel. Extraction rejects absolute paths,
  `..`, symlinks/hardlinks escaping the workspace and device files.
- **Errors** map to hints: 401 → "token invalid or expired", 403 with
  `X-RateLimit-Remaining: 0` → "rate limited until <reset>", 404 on a private repo
  → "token lacks access to this repo".
- **No GitHub Enterprise** in v0.1 (base URL fixed); backlog item.
- No new Go dependency: `net/http`, `archive/tar`, `compress/gzip` from stdlib.

## Alternatives considered
- `git clone` via go-git: more data (history), new dependency; history secret
  scanning is Phase 5.
- google/go-github: large dependency for five endpoints.

## Consequences
- README lists these calls (BST-034).
- GitHub API unit tests use `httptest` fakes only (§9.5); no live calls in CI.
