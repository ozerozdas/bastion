import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// The fix plan tab is stubbed: one package with two CVEs becomes one upgrade
// step, and a package without a fixed version lands in "No fix available" (#27).
const alpha = {
  id: 1,
  kind: 'path',
  display_name: 'alpha',
  ref: '/tmp/alpha',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 1, high: 2, medium: 0, low: 0, unknown: 0 },
}

const baseFinding = {
  scan_id: 1,
  type: 'vulnerability',
  package_name: 'lodash',
  package_version: '4.17.0',
  fixed_version: '4.17.21',
  location: 'package-lock.json:1',
  occurrences: 1,
  scanner: 'trivy',
  status: 'open',
  description: 'A vulnerability in a dependency.',
  references: [],
  scanners: ['trivy'],
}

const findings = [
  {
    ...baseFinding,
    id: 1,
    asset_id: alpha.id,
    fingerprint: 'fp-lodash-critical',
    rule_id: 'CVE-2021-1111',
    severity: 'critical',
    title: 'Prototype pollution in lodash',
  },
  {
    ...baseFinding,
    id: 2,
    asset_id: alpha.id,
    fingerprint: 'fp-lodash-high',
    rule_id: 'CVE-2021-2222',
    severity: 'high',
    title: 'Command injection in lodash',
  },
  {
    ...baseFinding,
    id: 3,
    asset_id: alpha.id,
    fingerprint: 'fp-openssl-high',
    rule_id: 'CVE-2022-3333',
    package_name: 'openssl',
    package_version: '1.1.1n',
    fixed_version: '',
    severity: 'high',
    title: 'Buffer overrun in openssl',
  },
]

const plan = {
  steps: [
    {
      ecosystem: 'npm',
      package: 'lodash',
      installed_versions: ['4.17.0'],
      target_version: '4.17.21',
      approximate: false,
      finding_count: 2,
      severity_counts: { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
      finding_ids: [1, 2],
      score: 17,
      factors: [
        { name: 'severity', value: 17, detail: '1 critical + 1 high' },
        { name: 'epss', value: 1, detail: 'EPSS off' },
        { name: 'latest_image', value: 1, detail: 'no image link' },
      ],
    },
  ],
  no_fix: [
    {
      ecosystem: 'npm',
      package: 'openssl',
      finding_count: 1,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
      finding_ids: [3],
    },
  ],
}

/** openFindings exchanges the startup token and lands on the Findings page. */
async function openFindings(page: Page, url: string) {
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await page.getByRole('link', { name: /^Findings/ }).click()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()
}

test('fix plan groups findings into one package upgrade per asset', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha] } }),
  )
  await page.route('**/api/assets/1/fix-plan', (route) =>
    route.fulfill({ json: plan }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({ json: { findings } }),
  )

  await openFindings(page, server.url)
  await page.getByRole('tab', { name: 'Fix plan' }).click()

  const origin = new URL(page.url()).origin
  await expect(page).toHaveURL(`${origin}/findings?tab=fix-plan`)
  // Without a project there is no plan: the tab explains the next step.
  await expect(
    page.getByRole('heading', { name: 'Choose a project' }),
  ).toBeVisible()

  await page.locator('#fix-plan-project').selectOption('1')
  await expect(page).toHaveURL(`${origin}/findings?tab=fix-plan&asset=1`)

  await expect(page.getByRole('heading', { name: 'Fix plan' })).toBeVisible()
  await expect(page.getByText(/1 upgrade close 2 findings/)).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'Score' })).toBeVisible()
  // The score explains itself: the weight sum and both omitted multipliers.
  await expect(
    page.getByRole('row', { name: /17.*severity 17.*EPSS off.*no image link/ }),
  ).toBeVisible()
  await expect(
    page.getByRole('row', { name: /Upgrade lodash.*4\.17\.21.*2 findings/ }),
  ).toBeVisible()

  await expect(
    page.getByRole('heading', { name: 'No fix available' }),
  ).toBeVisible()
  await expect(page.getByText('openssl')).toBeVisible()

  // A row expands to its findings; the drawer opens from one of them.
  await page.getByRole('row', { name: /Upgrade lodash/ }).click()
  await expect(page.getByText('CVE-2021-1111')).toBeVisible()
  await page.getByRole('button', { name: /CVE-2021-1111/ }).click()
  await expect(page.getByRole('dialog')).toBeVisible()

  expect(problems).toEqual([])
})
