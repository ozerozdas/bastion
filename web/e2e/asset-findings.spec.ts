import { expect, stubLicencePolicy, test, watch } from './fixtures'

const asset = {
  id: 4,
  kind: 'repo',
  display_name: 'acme/widgets',
  ref: 'acme/widgets',
  created_at: '2026-01-01T00:00:00Z',
  scan_schedule: 'off',
  linked_images: [],
  last_scan: { scan_id: 12, status: 'succeeded', finished_at: '2026-11-18T10:00:00Z' },
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
}

test('reviews and rescans one asset on its own page', async ({ page, server }) => {
  const problems = watch(page)
  await stubLicencePolicy(page)
  const started: unknown[] = []
  await page.route('**/api/assets', (route) => route.fulfill({ json: { assets: [asset] } }))
  await page.route('**/api/assets/4/fix-plan', (route) =>
    route.fulfill({ json: { steps: [], no_fix: [] } }),
  )
  await page.route('**/api/findings?*', (route) =>
    route.fulfill({ json: { findings: [], total: 0, page: 1, page_size: 50 } }),
  )
  await page.route('**/api/scans', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    started.push(route.request().postDataJSON())
    await route.fulfill({ status: 202, json: { scans: [] } })
  })

  await page.goto(server.url)
  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible()
  const origin = new URL(page.url()).origin

  // An old filtered link lands on the asset page and keeps its other filters.
  await page.goto(`${origin}/findings?asset=4&q=lodash`)
  await expect(page).toHaveURL(`${origin}/findings/4?q=lodash`)

  const header = page.getByRole('region', { name: 'acme/widgets' })
  await expect(header.getByRole('link', { name: 'Changes' })).toHaveAttribute(
    'href',
    '/scans/12/diff',
  )
  await header.getByRole('button', { name: 'Rescan' }).click()
  await expect.poll(() => started.length).toBe(1)

  // Searching stays on the asset page.
  await page.locator('#findings-search').fill('axios')
  await expect(page).toHaveURL(`${origin}/findings/4?q=axios`)

  await header.getByRole('link', { name: 'Fix plan' }).click()
  await expect(page).toHaveURL(`${origin}/findings/4?tab=fix-plan`)

  // An unknown asset falls back to every project.
  await page.goto(`${origin}/findings/999`)
  await expect(page).toHaveURL(`${origin}/findings`)

  expect(problems).toEqual([])
})
