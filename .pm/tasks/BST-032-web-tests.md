---
id: BST-032
title: "Frontend tests: Vitest logic + Playwright smoke for 5 pages"
phase: P1
status: done
owner_role: tester
depends_on: [BST-026, BST-027, BST-028, BST-029, BST-030]
estimate: M
---

## Context
§9.5.

## Scope
- In: Vitest for non-trivial client logic; Playwright smoke that starts `bastion serve` against a seeded temp data dir, exchanges the token, and loads all 5 pages without console errors. Run in CI.

## Acceptance criteria
- [x] Dependency justification in log (vitest, @playwright/test)
- [x] CI job green (job added and `make e2e` green locally; CI run happens on push)

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

- Two devDependencies, both pinned exact:
  - `vitest@5.1.0` — runs on the Vite 8 config the repo already has (no
    separate transformer or jsdom), so unit tests cost no extra setup.
  - `@playwright/test@1.65.0` — the smoke test needs a real browser against the
    real binary; Chromium is the only downloaded browser.
- Pure helpers moved to `web/src/lib/` to test them without rendering:
  `time.ts` (`relativeTime`, `formatDateTime`, `scanDuration`; the three page
  copies now share it), `hints.ts` (`suggestFix`), `urls.ts` (`isHttpsUrl`).
  `filterParams` in `web/src/api/findings.ts` is exported but stays in place.
- Tests: `web/src/lib/*.test.ts` and `web/src/api/findings.test.ts` (21 tests).
  `npm run test` runs `vitest run`; `make web-check` runs it, so `make check`
  covers it. `make e2e` (depends on `build`) is NOT part of `make check`.
- `web/e2e/fixtures.ts` starts `bin/bastion serve --no-browser --port 0
  --data-dir <tmp> --cache-dir <tmp>` with `BASTION_HMAC_KEY` set, per test, and
  stops it with SIGTERM (SIGKILL after 5s). The URL line is written to stderr by
  `serve`, so both stdout and stderr are scanned; the fixture then adds a local
  path project and the spec asserts every nav page renders with no console,
  page or 5xx API errors. Browser's automatic `/favicon.ico` 404 is ignored
  (the bundle ships no favicon). No scan is started (needs the Trivy DB).
- CI: new `e2e` job (`needs: check`) builds, installs Chromium with deps, runs
  `make e2e`, uploads `web/playwright-report` on failure.
- Verification run locally (node 26.3.0, npm 11.16.0, macOS arm64):
  - `npm --prefix web run typecheck` — clean
  - `npm --prefix web run test` — 4 files, 21 tests passed
  - `npx --prefix web playwright install chromium` — Chrome Headless Shell
    158.0.8127.18 downloaded
  - `make e2e` — 3 passed (9.8s)
  - `make check` — passed (fmt, lint, vitest+typecheck, web build, go test,
    build)
- CI itself could not be observed from this branch (no push allowed); the job
  mirrors the locally green `make build` + `make e2e` sequence.
