---
id: BST-021
title: GitHub tarball source (internal/sources/github)
phase: P1
status: done
owner_role: coder
depends_on: [BST-019]
estimate: M
---

## Context
§4.2 Source interface, ADR-005 budgets, §4.4 workspaces.

## Scope
- In: `Source` for `repo`: ref `owner/repo@sha` → download tarball → extract into `<cache>/workspaces/<random>` with the strip-top-dir GitHub layout → `Cleanup` removes it (unless keep-workspace). Safe extraction per ADR-005.
- Out: git history (P5).

## Acceptance criteria
- [x] Tests with crafted tarballs: `../x`, absolute path, symlink escaping, hardlink, device file, oversize, too many files → all rejected or skipped with a reported reason
- [x] Cancel mid-download removes the partial workspace
- [x] `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

2026-11-11 — coder

New package `internal/sources/github` (stdlib only, no new deps):

- `github.New(dl Downloader, opts Options) (*Source, error)`; `Downloader` is
  just `Tarball(ctx, owner, name, sha) (io.ReadCloser, error)`, satisfied by
  `*connections/github.Client`. `Kind()` returns `sources.KindRepo`.
- Ref parsing is strict: `owner/repo@sha` with exactly one `/` and one `@`,
  owner/repo `[A-Za-z0-9._-]`, sha 40 hex (stored lower-case for `Tarball`).
- `Options`: `WorkspacesDir` (required), `KeepWorkspace` (spec §4.4), extraction
  budgets `MaxExtractBytes` (default 2 GiB) / `MaxFiles` (default 200 000),
  `Logger` (nil → `slog.Default()`).
- Extraction: gzip+tar, top-level `owner-repo-sha/` stripped; only regular files
  and dirs are written (via `os.Root`); absolute or `..`-escaping entry names
  fail the fetch, symlinks/hardlinks/device/fifo entries are skipped and counted.
  Modes sanitized to 0o644 / 0o755 (exec bit) and dirs 0o755, chmod'ed so the
  umask cannot weaken them. Skips are reported in one `Warn` line (counts per
  category) plus a `Debug` summary; neither logs a URL.
- `ctx` is checked between entries and before every tarball read, so a cancel
  interrupts a large file copy; any error (including download errors) removes
  the partial workspace dir. `Cleanup` removes the dir, no-op with
  `KeepWorkspace`.
- Tests (`github_test.go`) build archives in-test with `archive/tar` +
  `compress/gzip`: strip-top-dir + content/modes, `../x` / absolute path (error +
  no dir left), symlink/hardlink/char/fifo skipped (not created, logged),
  byte and file budgets, cancel mid-read (blocking fake reader, workspace
  removed), 13 bad refs, wrong kind, download error, `KeepWorkspace`.

Commands run:
- `gofmt -l internal/sources` → no output
- `go vet ./internal/sources/...` → clean
- `go test -race -count=1 ./internal/sources/...` → ok
- `GODEBUG=tarinsecurepath=0 go test ./internal/sources/github/` → ok (fails
  closed with the tar reader's own path check too)
- `go tool golangci-lint run ./internal/sources/...` → 0 issues
- `make check` → exit 0 (fmt, 0 lint issues, web typecheck/build, `go test ./...`,
  `go build -o bin/bastion`)

Wiring (`<cache>/workspaces` from `app.Paths`, real client) belongs to
BST-022/BST-031; nothing here imports `internal/app`.

