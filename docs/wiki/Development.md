# Development

## Requirements

- Go 1.27+ (dev tools are pinned in `tools/go.mod` and run with `go tool -modfile=tools/go.mod …` — no global installs)
- Node 24 (for the web UI)

## Everyday commands

```sh
make build   # web UI → web/dist, then bin/bastion with the UI embedded
make check   # web typecheck + tests, web build, gofmt, golangci-lint, go test, go build
make test    # go test ./...
make gen     # sqlc + oapi-codegen + openapi-typescript
make e2e     # Playwright smoke test against the real binary
```

`make e2e` needs a browser once: `npx --prefix web playwright install chromium`.

Run `make check` before every commit; CI runs the same thing.

## Making changes

| Changing… | Do this |
|---|---|
| The API | Edit `api/openapi.yaml` first, then `make gen`, then implement |
| The database schema | Add a new goose migration in `db/migrations/` + queries in `db/queries/`, then `make gen` |
| SQL queries | Keep `db/queries/*.sql` ASCII-only (sqlc corrupts non-ASCII input; `make gen` checks this) |
| A normalizer | Update golden tests in `testdata/`; regenerate goldens only with `-update` and explain why |
| Outbound network calls | Needs an ADR and an entry in the README's *Network calls* table |
| Dependencies | Prefer the stdlib; justify any new Go or npm dependency |

## Tests

- **Normalizers and diff** — golden tests: raw scanner output → expected JSON.
- **Store** — against a temporary SQLite file.
- **GitHub and other external APIs** — interfaces + fakes; no live calls in unit tests.
- **Frontend** — Vitest for logic, Playwright smoke test for every sidebar section.

## Releases

GoReleaser builds darwin/linux/windows × amd64/arm64, publishes the Homebrew cask and
`checksums.txt`. Try it locally without publishing:

```sh
make release-snapshot   # → dist/
```

## Project management

Tasks, phases and decisions live in `.pm/` (`BOARD.md`, `tasks/`, `decisions/`). The
rulebook is [`PROJECT_SPEC.md`](../../PROJECT_SPEC.md).
