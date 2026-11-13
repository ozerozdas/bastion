import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// The dashboard aggregates every project; these tests stub that payload so the
// project links are present without a real scan (#108).
const alpha = {
  id: 1,
  kind: 'path',
  display_name: 'alpha',
  ref: '/tmp/alpha',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
}

const beta = {
  id: 2,
  kind: 'repo',
  display_name: 'beta',
  ref: 'acme/beta',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
}

const dashboard = {
  totals_by_severity: { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
  totals_by_type: {
    vulnerability: 2,
    secret: 0,
    outdated: 0,
    misconfig: 0,
    license: 0,
    malware: 0,
    sast: 0,
  },
  // The trend rows carry only an asset id; the riskiest list supplies the names.
  top_assets: [
    {
      asset_id: alpha.id,
      display_name: alpha.display_name,
      kind: alpha.kind,
      score: 10,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
    },
  ],
  trend: [
    {
      asset_id: alpha.id,
      scans: [
        {
          scan_id: 3,
          finished_at: '2026-01-02T00:00:00Z',
          critical_high_open: 1,
        },
      ],
    },
  ],
  last_scans: [
    {
      asset_id: beta.id,
      display_name: beta.display_name,
      scan_id: 4,
      status: 'succeeded',
      finished_at: '2026-01-03T00:00:00Z',
    },
  ],
}

/** dashboardSection scopes locators to the section with that heading. */
function dashboardSection(page: Page, name: string) {
  return page
    .locator('section')
    .filter({ has: page.getByRole('heading', { name }) })
}

test('dashboard project names link to their filtered findings', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.route('**/api/reports/dashboard', (route) =>
    route.fulfill({ json: dashboard }),
  )
  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({ json: { findings: [] } }),
  )

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  const origin = new URL(page.url()).origin

  // Open critical and high: the trend row's project name goes to its findings.
  await dashboardSection(page, 'Open critical and high')
    .getByRole('link', { name: 'alpha' })
    .click()
  await expect(page).toHaveURL(`${origin}/findings?asset=${String(alpha.id)}`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()
  await expect(page.locator('#findings-project')).toHaveValue(String(alpha.id))

  // Back to the dashboard for the last-scan table's own project link.
  await page.goBack()
  await dashboardSection(page, 'Last scan per project')
    .getByRole('link', { name: 'beta' })
    .click()
  await expect(page).toHaveURL(`${origin}/findings?asset=${String(beta.id)}`)
  await expect(page.locator('#findings-project')).toHaveValue(String(beta.id))

  expect(problems).toEqual([])
})
