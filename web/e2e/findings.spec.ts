import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// These tests stub the API so the cross-project list has findings without a
// real scan, and so a redirect test can rely on one project existing.
const alpha = {
  id: 1,
  kind: 'path',
  display_name: 'alpha',
  ref: '/tmp/alpha',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
}

const beta = {
  id: 2,
  kind: 'repo',
  display_name: 'beta',
  ref: 'acme/beta',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 1, high: 0, medium: 1, low: 0, unknown: 0 },
}

const baseFinding = {
  scan_id: 1,
  type: 'vulnerability',
  rule_id: 'CVE-2020-0001',
  package_name: 'lodash',
  package_version: '4.17.0',
  fixed_version: '4.17.21',
  location: 'package-lock.json:1',
  occurrences: 1,
  scanner: 'trivy',
  status: 'open',
  description: 'A vulnerability in a dependency.',
  references: ['https://example.com/advisory'],
}

const findings = [
  {
    ...baseFinding,
    id: 1,
    asset_id: beta.id,
    fingerprint: 'fp-beta-critical',
    severity: 'critical',
    title: 'Critical in beta',
  },
  {
    ...baseFinding,
    id: 2,
    asset_id: alpha.id,
    fingerprint: 'fp-alpha-high',
    severity: 'high',
    title: 'High in alpha',
  },
  {
    ...baseFinding,
    id: 3,
    asset_id: beta.id,
    fingerprint: 'fp-beta-medium',
    severity: 'medium',
    title: 'Medium in beta',
  },
]

/** openDashboard exchanges the startup token and waits for the shell. */
async function openDashboard(page: Page, url: string) {
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
}

test('lists findings across projects with no filter, critical first', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const requested: URL[] = []

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) => {
    const url = new URL(route.request().url())
    requested.push(url)
    const assetId = url.searchParams.get('asset_id')
    const rows =
      assetId === null
        ? findings
        : findings.filter((finding) => finding.asset_id === Number(assetId))
    return route.fulfill({ json: { findings: rows } })
  })

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()

  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'Project' })).toBeVisible()
  await expect(page.locator('#findings-project')).toHaveValue('')

  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(3)
  // Severity order comes from the API; the list must not regroup it by project.
  await expect(rows.nth(0)).toContainText('Critical in beta')
  await expect(rows.nth(0)).toContainText('beta')
  await expect(rows.nth(1)).toContainText('High in alpha')
  await expect(rows.nth(1)).toContainText('alpha')

  // No project filter means no asset_id reaches the API.
  expect(requested.length).toBeGreaterThan(0)
  for (const url of requested) {
    expect(url.searchParams.has('asset_id')).toBe(false)
  }

  // The Project filter narrows the same list to one project.
  requested.length = 0
  const origin = new URL(page.url()).origin
  await page.locator('#findings-project').selectOption(String(beta.id))
  await expect(rows).toHaveCount(2)
  await expect(rows.nth(0)).toContainText('beta')
  await expect(page).toHaveURL(`${origin}/findings?asset=${String(beta.id)}`)
  expect(requested.at(-1)?.searchParams.get('asset_id')).toBe(String(beta.id))

  // Back to every project.
  await page.locator('#findings-project').selectOption('')
  await expect(rows).toHaveCount(3)
  await expect(page).toHaveURL(`${origin}/findings`)

  expect(problems).toEqual([])
})

test('redirects old report URLs to the findings list', async ({ page, server }) => {
  const problems = watch(page)
  const asset = { ...alpha, id: 42, display_name: 'forty-two' }

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [asset] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({ json: { findings: [] } }),
  )

  await openDashboard(page, server.url)
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/reports?asset=${String(asset.id)}`)
  await expect(page).toHaveURL(`${origin}/findings?asset=${String(asset.id)}`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Findings' }),
  ).toBeVisible()
  await expect(page.locator('#findings-project')).toHaveValue(String(asset.id))

  await page.goto(`${origin}/reports`)
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.locator('#findings-project')).toHaveValue('')

  // The name the previous UI used keeps working too.
  await page.goto(`${origin}/security-reports?asset=${String(asset.id)}`)
  await expect(page).toHaveURL(`${origin}/findings?asset=${String(asset.id)}`)

  expect(problems).toEqual([])
})
