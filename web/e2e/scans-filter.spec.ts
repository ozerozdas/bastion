import { expect, test, watch } from './fixtures'

// The API is stubbed so the Scans tab has two projects with one scan each.
const asset = (id: number, name: string) => ({
  id,
  kind: 'path',
  display_name: name,
  ref: `/tmp/${name}`,
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
})
const alpha = asset(1, 'alpha')
const beta = asset(2, 'beta')

const scan = (id: number, assetId: number) => ({
  id,
  asset_id: assetId,
  status: 'succeeded',
  trigger: 'ui',
  started_at: '2026-01-01T00:00:00Z',
  finished_at: '2026-01-01T00:00:05Z',
})
const scans = [scan(1, alpha.id), scan(2, beta.id)]

test('keeps the Scans project filter in the URL (#54)', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/scans?**', (route) => {
    const assetId = new URL(route.request().url()).searchParams.get('asset_id')
    const rows =
      assetId === null
        ? scans
        : scans.filter((s) => s.asset_id === Number(assetId))
    return route.fulfill({ json: { scans: rows } })
  })

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/projects?tab=scans`)
  const filter = page.locator('#scan-asset-filter')
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(2)

  // Selecting a project updates the URL.
  await filter.selectOption(String(beta.id))
  await expect(page).toHaveURL(
    `${origin}/projects?tab=scans&asset=${String(beta.id)}`,
  )
  await expect(rows).toHaveCount(1)

  // Reload restores it.
  await page.reload()
  await expect(filter).toHaveValue(String(beta.id))
  await expect(rows).toHaveCount(1)

  // All projects clears it.
  await filter.selectOption('')
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)
  await expect(rows).toHaveCount(2)

  // A removed project's id is dropped rather than showing an empty list.
  await page.goto(`${origin}/projects?tab=scans&asset=999`)
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)
  await expect(filter).toHaveValue('')

  expect(problems).toEqual([])
})
