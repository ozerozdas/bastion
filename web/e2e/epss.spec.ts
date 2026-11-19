import type { Page } from '@playwright/test'

import { expect, openConfiguration, test, watch } from './fixtures'

// The EPSS feed is stubbed: the e2e server must never reach FIRST.org, and the
// tests need a deterministic score date and count.
const asset = {
  id: 1,
  kind: 'path',
  display_name: 'demo',
  ref: '/tmp/demo',
  created_at: '2026-01-01T00:00:00Z',
  last_scan: { scan_id: 1, status: 'succeeded' },
  open_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
}

const finding = {
  id: 1,
  asset_id: 1,
  scan_id: 1,
  fingerprint: 'fp-epss',
  type: 'vulnerability',
  severity: 'critical',
  title: 'Remote code execution in log4j',
  rule_id: 'CVE-2021-44228',
  package_name: 'log4j-core',
  package_version: '2.14.0',
  fixed_version: '2.17.0',
  location: 'pom.xml:1',
  occurrences: 1,
  scanner: 'trivy',
  scanners: ['trivy'],
  status: 'open',
  description: 'A vulnerability in a dependency.',
  references: [],
  epss: { score: 0.99999, percentile: 1.0 },
}

/**
 * stubEPSS answers /api/epss from in-page state. `enabled` starts off, so the
 * default page proves the off setting renders no EPSS anywhere.
 */
async function stubEPSS(page: Page, enabled = false, scores = enabled) {
  let on = enabled
  const body = () =>
    on
      ? {
          enabled: true,
          count: 406615,
          score_date: '2026-11-15T12:03:04Z',
          last_refresh: '2026-11-15T12:05:00Z',
        }
      : { enabled: false }
  await page.route('**/api/epss', async (route) => {
    if (route.request().method() === 'PUT') {
      const { enabled: next } = route.request().postDataJSON() as { enabled: boolean }
      on = next
    }
    await route.fulfill({ json: body() })
  })
  await page.route('**/api/assets', (route) => route.fulfill({ json: { assets: [asset] } }))
  await page.route('**/api/findings?**', (route) => {
    // The server omits `epss` from findings while the feed is off, so the
    // off test stubs exactly that; the on test needs the score present.
    const rows = [scores ? finding : { ...finding, epss: undefined }]
    return route.fulfill({
      json: {
        findings: rows,
        groups: [],
        total: rows.length,
        total_findings: rows.length,
        limit: 50,
        offset: 0,
      },
    })
  })
}

/** openFindings opens the single-row findings table. */
async function openFindings(page: Page, url: string) {
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await page.getByRole('button', { name: 'Single' }).click()
  await expect(page.locator('tbody tr')).toHaveCount(1)
}

test('EPSS is off by default and renders no scores', async ({ page, server }) => {
  const problems = watch(page)
  await stubEPSS(page, false)
  await openFindings(page, server.url)

  // The setting lives in the Configuration modal, not the sidebar.
  await expect(
    page.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toHaveCount(0)
  await openConfiguration(page)

  const card = page.getByRole('region', { name: 'EPSS exploit scores' })
  await expect(card).toBeVisible()
  await expect(card.getByText('Off', { exact: true })).toBeVisible()
  await expect(
    card.getByRole('switch', { name: 'EPSS exploit scores' }),
  ).toHaveAttribute('aria-checked', 'false')
  // Back to the findings list the page was opened from.
  await page.goBack()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()

  await expect(page.getByRole('columnheader', { name: 'EPSS' })).toHaveCount(0)

  await page.locator('tbody tr').first().click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByRole('dialog').getByText(/^EPSS /)).toHaveCount(0)

  expect(problems).toEqual([])
})

test('turning EPSS on shows the feed and the finding score', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await stubEPSS(page, false, true)
  await openFindings(page, server.url)

  await openConfiguration(page)
  await page.getByRole('switch', { name: 'EPSS exploit scores' }).click()

  await expect(page.getByText('406,615 CVEs · 2026-11-15')).toBeVisible()
  await page.goBack()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'EPSS' })).toBeVisible()
  await expect(page.getByRole('cell', { name: /1\.00/ })).toBeVisible()

  await page.locator('tbody tr').first().click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByText('EPSS 1.00 · 100th pct')).toBeVisible()

  expect(problems).toEqual([])
})
