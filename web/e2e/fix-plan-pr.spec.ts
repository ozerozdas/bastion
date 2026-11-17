import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// Opening a manifest pull request (#47) is a deliberate two-step action: the
// dialog explains what will happen on GitHub, and no request leaves the page
// until the user confirms.
const repo = {
  id: 1,
  kind: 'repo',
  connection_id: 1,
  display_name: 'acme/app',
  ref: 'acme/app',
  default_branch: 'main',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
}

const finding = {
  id: 1,
  asset_id: repo.id,
  scan_id: 1,
  fingerprint: 'fp-lodash-high',
  type: 'vulnerability',
  rule_id: 'CVE-2021-2222',
  severity: 'high',
  title: 'Command injection in lodash',
  package_name: 'lodash',
  package_version: '4.17.0',
  fixed_version: '4.17.21',
  ecosystem: 'npm',
  location: 'package-lock.json:1',
  occurrences: 1,
  scanner: 'trivy',
  status: 'open',
  description: 'A vulnerability in a dependency.',
  references: [],
  scanners: ['trivy'],
}

const plan = {
  steps: [
    {
      ecosystem: 'npm',
      package: 'lodash',
      installed_versions: ['4.17.0'],
      target_version: '4.17.21',
      approximate: false,
      finding_count: 1,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
      finding_ids: [1],
      score: 7,
      factors: [
        { name: 'severity', value: 7, detail: '1 high' },
        { name: 'epss', value: 1, detail: 'EPSS off' },
        { name: 'latest_image', value: 1, detail: 'no image link' },
      ],
    },
  ],
  no_fix: [],
}

/** openFixPlan exchanges the token, opens Findings and selects the project. */
async function openFixPlan(page: Page, url: string) {
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await page.getByRole('link', { name: /^Findings/ }).click()
  await page.getByRole('tab', { name: 'Fix plan' }).click()
  await page.locator('#fix-plan-project').selectOption('1')
  await expect(page.getByRole('heading', { name: 'Fix plan' })).toBeVisible()
}

test('open PR asks for confirmation before any request', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  let posted = 0

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [repo] } }),
  )
  await page.route('**/api/assets/1/fix-plan', (route) =>
    route.fulfill({ json: plan }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({
      json: {
        findings: [finding],
        groups: [],
        total: 1,
        total_findings: 1,
        limit: 500,
        offset: 0,
      },
    }),
  )
  await page.route('**/api/assets/1/fix-plan/pull-request', (route) => {
    posted += 1
    return route.fulfill({
      json: {
        url: 'https://github.com/acme/app/pull/12',
        number: 12,
        branch: 'bastion/bump-lodash-4.17.21',
        manifest: 'package.json',
      },
    })
  })

  await openFixPlan(page, server.url)

  await page.getByRole('button', { name: 'Open PR' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('lodash')).toBeVisible()
  await expect(dialog.getByText('4.17.21')).toBeVisible()
  // The dialog names the sibling manifest the scanner's lockfile maps to.
  await expect(dialog.getByText('package.json')).toBeVisible()
  await expect(
    dialog.getByText(/Regenerate the lockfile \(go mod tidy \/ npm install\)/),
  ).toBeVisible()

  // Nothing has been sent yet: closing the dialog would create no branch.
  expect(posted).toBe(0)

  await dialog.getByRole('button', { name: 'Open pull request' }).click()
  await expect(
    dialog.getByRole('link', { name: 'https://github.com/acme/app/pull/12' }),
  ).toBeVisible()
  await expect(dialog.getByText('Manifest changed: package.json')).toBeVisible()
  expect(posted).toBe(1)

  expect(problems).toEqual([])
})

test('a recorded pull request replaces the Open PR button', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const url = 'https://github.com/acme/app/pull/12'

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [repo] } }),
  )
  await page.route('**/api/assets/1/fix-plan', (route) =>
    route.fulfill({
      json: {
        ...plan,
        steps: [
          {
            ...plan.steps[0],
            pull_request: { number: 12, url, state: 'open' },
          },
        ],
      },
    }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({
      json: {
        findings: [finding],
        groups: [],
        total: 1,
        total_findings: 1,
        limit: 500,
        offset: 0,
      },
    }),
  )

  await openFixPlan(page, server.url)

  await expect(page.getByRole('link', { name: 'PR #12 open' })).toHaveAttribute(
    'href',
    url,
  )
  await expect(page.getByRole('button', { name: 'Open PR' })).toHaveCount(0)

  expect(problems).toEqual([])
})
