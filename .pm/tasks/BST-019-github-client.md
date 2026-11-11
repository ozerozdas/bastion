---
id: BST-019
title: GitHub API client (internal/connections/github)
phase: P1
status: done
owner_role: coder
depends_on: [BST-015]
estimate: M
---

## Context
ADR-005. Five endpoints, stdlib only.

## Scope
- In: client with injectable base URL + `http.Client`: `User`, `ListRepos` (Link pagination), `Repo`, `ResolveSHA`, `Tarball` (returns body reader, follows redirect, size cap). Error mapping with hints per ADR-005. Request URLs never logged.
- Out: storing tokens (020), extraction (021).

## Acceptance criteria
- [x] httptest fake covers: pagination, 401, rate-limit 403, 404, redirect to another host drops `Authorization`
- [x] No token or URL query string in any log line (test with a capturing slog handler)
- [x] No new dependency; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

### 2026-11-11 — implemented (bst-019-github-client)

Package `internal/connections/github`, stdlib only (`net/http`, `encoding/json`,
`log/slog`, `io`, `net/url`); `go.mod` unchanged.

Public API:
- `New(Config) (*Client, error)` — `Config{Token (required), BaseURL, HTTPClient,
  Version, MaxTarballBytes, Logger}`.
- `(*Client) User(ctx) (User, error)`, `ListRepos(ctx) ([]Repo, error)`,
  `Repo(ctx, owner, name) (Repo, error)`, `ResolveSHA(ctx, owner, name, ref) (string, error)`,
  `Tarball(ctx, owner, name, sha) (io.ReadCloser, error)`.
- Types `User`, `Owner`, `Repo{FullName, Name, Owner, DefaultBranch, Private, Archived}`.
- `Error{Op, StatusCode, Hint, Err}` with `Unwrap`; `errors.As(err, **github.Error)`
  gives the user-facing `Hint` (401 → token invalid or expired; 403 +
  `X-RateLimit-Remaining: 0` → `rate limited until <RFC3339 reset>`;
  404 → repo not found or token lacks access; anything else → bare status).

Decisions:
- **Headers** on every API call: `Authorization: Bearer <tok>`, `Accept:
  application/vnd.github+json` (or `application/vnd.github.sha` for ResolveSHA),
  `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: bastion/<Version>`
  (`bastion/dev` when Version is empty). No personal data in the UA.
- **ListRepos**: `per_page=100&sort=pushed`, follows `Link rel="next"`, capped at
  `maxRepoPages = 50` (5 000 repos). Hitting the cap returns an error instead of
  a silently truncated list. A `rel="next"` pointing at another host is refused
  (that target would receive `Authorization`).
- **Ref validation — deviation from the task wording, flagged for review.** The
  task said reject `/` in `ref`. I allow slash-separated refs (`release/2.x` is a
  common default branch) but validate every segment: no empty, `.` or `..`
  segment, no `\ ? #` or control characters. Owner, repo and SHA stay
  single-segment. Without this, resolving a default branch such as `release/2.x`
  would fail. Rejecting `..` keeps the request inside `/commits/{ref}`.
- **Redirects**: no custom `CheckRedirect`; `net/http` already drops
  `Authorization` when the host changes, and `TestTarballRedirectDropsAuthorization`
  proves it (redirect to `localhost` from `127.0.0.1`, asserts the second server
  saw no `Authorization`).
- **Tarball**: 302 followed to codeload; body wrapped in a `cappedReader` that
  fails once `MaxTarballBytes` (default 512 MiB) is exceeded — never truncates
  silently. `Content-Length` over the cap is rejected before reading.
- **No URLs in logs/errors**: log lines are `op` + HTTP status only
  ("get repo owner/name"), errors name the operation and `owner/repo@sha`.
  `*url.Error` is unwrapped so its embedded URL never reaches the message;
  GitHub response bodies are not read into errors. `TestSecretsNeverLogged`
  captures slog JSON and asserts neither the token nor `token=` appears.
- `io.LimitReader` (8 MiB) bounds JSON bodies; a SHA response is bounded at 128
  bytes and validated as 40 hex characters, returned lower-case.

Verification:
- `go test -race ./internal/connections/...` → ok (all tests; the redirect test
  runs, not skipped).
- `go vet ./...` → pass (needs `web/dist`; built with `npm ci --prefix web` +
  `npm run build --prefix web`).
- `go tool golangci-lint run ./internal/connections/...` → 0 issues.
- `gofmt -l .` → empty.
- `make check` (fmt, lint, web-check, web-build, test, build) → pass.

Not done here: README "Network calls" section (BST-034), token storage (BST-020),
extraction (BST-021).

### 2026-11-11 — review (orchestrator)
- Accepted deviation: slash-separated refs allowed, each segment validated (branches like release/2.x).
