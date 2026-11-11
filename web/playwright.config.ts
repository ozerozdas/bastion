import { defineConfig } from '@playwright/test'

// The smoke test drives the real binary: e2e/fixtures.ts starts
// `bin/bastion serve` against a throwaway data dir for every test. Chromium is
// the only browser installed in CI, so it is the only project.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
