import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

// The drawer needs a project with findings; the API is stubbed so the tests do
// not depend on a real scan.
const asset = {
  id: 1,
  kind: 'path',
  display_name: 'demo',
  ref: '/tmp/demo',
  created_at: '2026-01-01T00:00:00Z',
  last_scan: { scan_id: 1, status: 'succeeded' },
  open_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
}

const baseFinding = {
  asset_id: 1,
  scan_id: 1,
  type: 'vulnerability',
  severity: 'critical',
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

const finding = { ...baseFinding, id: 1, fingerprint: 'fp-1', title: 'Example finding' }

const findings = [
  finding,
  { ...baseFinding, id: 2, fingerprint: 'fp-2', title: 'Second finding' },
  { ...baseFinding, id: 3, fingerprint: 'fp-3', title: 'Third finding' },
]

/**
 * openReports stubs the reports API and opens the page. `list` answers the
 * findings request until a decision is saved; the refetch that follows a
 * decision gets `afterDecision`, as the server returns it once the row left
 * this status-filtered list.
 */
async function openReports(
  page: Page,
  url: string,
  list: (typeof findings)[number][] = [finding],
  afterDecision: (typeof findings)[number][] = [],
) {
  let current = list
  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [asset] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill({ json: { findings: current } }),
  )
  await page.route('**/api/findings/*/state', (route) => {
    current = afterDecision
    return route.fulfill({ status: 204 })
  })
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.locator('tbody tr')).toHaveCount(list.length)
}

/** decide opens the drawer on one row and saves a decision for it. */
async function decide(page: Page, rowIndex: number) {
  await page.locator('tbody tr').nth(rowIndex).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.getByLabel('Reason').fill('Tested; this one does not apply here.')
  await page.getByRole('button', { name: 'Save decision' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
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
  for (const key of [...Array<string>(8).fill('Tab'), ...Array<string>(8).fill('Shift+Tab')]) {
    await page.keyboard.press(key)
    expect(await page.evaluate(focusInDialog), `after ${key}`).toBe(true)
  }

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(row).toBeFocused()

  expect(problems).toEqual([])
})

test('a decision that removes a row focuses the next finding', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openReports(page, server.url, findings, [findings[0], findings[2]])

  await decide(page, 1)

  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(2)
  await expect(rows.nth(1)).toContainText('Third finding')
  await expect(rows.nth(1)).toBeFocused()

  expect(problems).toEqual([])
})

test('a decision that removes the last row focuses the previous finding', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openReports(page, server.url, findings, findings.slice(0, 2))

  await decide(page, 2)

  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(2)
  await expect(rows.nth(1)).toContainText('Second finding')
  await expect(rows.nth(1)).toBeFocused()

  expect(problems).toEqual([])
})

test('a decision that empties the list focuses the findings heading', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openReports(page, server.url, [finding], [])

  await decide(page, 0)

  await expect(page.locator('tbody tr')).toHaveCount(0)
  await expect(
    page.getByRole('heading', { name: 'No open findings in the latest scan' }),
  ).toBeFocused()

  expect(problems).toEqual([])
})
