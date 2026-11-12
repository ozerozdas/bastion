import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// The drawer needs a project with a finding; the API is stubbed so the test
// does not depend on a real scan.
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
  fingerprint: 'fp-1',
  type: 'vulnerability',
  severity: 'critical',
  title: 'Example finding',
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

async function openReports(page: Page, url: string) {
  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [asset] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({ json: { findings: [finding] } }),
  )

  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await page.getByRole('link', { name: 'Security Reports', exact: true }).click()
  await expect(page.locator('tbody tr')).toHaveCount(1)
}

const focusInDialog = () =>
  document.querySelector('[role="dialog"]')?.contains(document.activeElement) ??
  false

test('the finding drawer traps Tab and gives focus back to its row', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openReports(page, server.url)

  const row = page.locator('tbody tr').first()
  await row.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog')).toBeVisible()

  // More presses than the drawer has controls: focus must wrap, not leave.
  for (const key of [
    ...Array<string>(8).fill('Tab'),
    ...Array<string>(8).fill('Shift+Tab'),
  ]) {
    await page.keyboard.press(key)
    expect(await page.evaluate(focusInDialog), `after ${key}`).toBe(true)
  }

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(row).toBeFocused()

  expect(problems).toEqual([])
})
