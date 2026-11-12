# Contributing

Thanks for helping. Bug reports, fixes and small focused PRs are welcome. For anything larger
(new scanner, new network call, schema or API shape change), open an issue first so we can
agree on the approach before you write code.

## Setup

Requirements: Go (version in `go.mod`), Node 24, make. Dev tools (sqlc, oapi-codegen,
golangci-lint) are pinned as `go.mod` tool directives and run via `go tool`; nothing to
install globally.

```sh
make check   # everything CI's check job runs: web typecheck + vitest, vite build, gofmt, lint, go test, go build
make e2e     # Playwright smoke test against the built binary
             # (once: npx --prefix web playwright install chromium)
make gen     # regenerate sqlc, Go server and TS client code
```

`make check` must pass before you open a PR.

## Rules that are easy to miss

- **Spec-first API.** Change `api/openapi.yaml` first, run `make gen`, then implement. Never
  hand-edit generated code (`internal/httpapi/gen`, `internal/store/sqlcdb`,
  `web/src/api/schema.d.ts`); commit the regenerated files with your change.
- **Schema changes** go in a new goose migration under `db/migrations/`, plus sqlc queries in
  `db/queries/`.
- **`db/queries/*.sql` must be ASCII-only.** sqlc silently emits corrupt SQL on non-ASCII
  input; `make gen` refuses to run if it finds any.
- **No new outbound network calls** without discussion: bastion promises that nothing leaves
  the machine except calls the user configured. Every call is listed in the README.
- **Never log, persist or return secrets**, including in test output.
- **New dependencies** need a one-line justification in the PR. Prefer the standard library.
- Tests: external APIs behind interfaces with fakes (no live calls in unit tests);
  normalizer changes come with golden tests in `testdata/` (update with `-update` and say why).

`PROJECT_SPEC.md` is the full rulebook (§9 engineering rules); `.pm/` holds tasks and
decision records.

## Commits and PRs

Commit subjects follow `type(scope): summary`, e.g. `feat(scan): --skip-dirs`,
`fix(store): ...`, `docs(readme): ...`. Common types: `feat`, `fix`, `docs`, `test`,
`build`, `ci`, `web`. Keep one logical change per PR; describe what changed and how you
verified it.

By contributing you agree that your contributions are licensed under Apache-2.0.
