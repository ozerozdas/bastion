import { expect, test, watch } from './fixtures'

// The API is stubbed so one project has three succeeded scans and one failed
// one, and the diff between scan 30 and its two baselines is known up front.
const asset = {
  id: 1,
  kind: 'path',
  display_name: 'alpha',
  ref: '/tmp/alpha',
  created_at: '2026-01-01T00:00:00Z',
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
}

const emptyCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
const oneCritical = { ...emptyCounts, critical: 1 }

const scan = (id: number, status: 'succeeded' | 'failed', counts = emptyCounts) => ({
  id,
  asset_id: asset.id,
  status,
  trigger: 'cli',
  started_at: '2026-01-01T00:00:00Z',
  finished_at: '2026-01-01T00:00:05Z',
  counts,
})

const scans = [
  scan(30, 'succeeded', oneCritical),
  scan(20, 'succeeded'),
  scan(10, 'succeeded'),
  scan(25, 'failed'),
]

const finding = (
  id: number,
  title: string,
  fingerprint: string,
  scanId: number,
) => ({
  id,
  asset_id: asset.id,
  scan_id: scanId,
  fingerprint,
  type: 'vulnerability',
  severity: 'critical',
  title,
  rule_id: 'CVE-2026-0001',
  package_name: 'lodash',
  package_version: '4.17.0',
  fixed_version: '4.17.21',
  location: 'package-lock.json:1',
  occurrences: 1,
  scanner: 'trivy',
  status: 'open',
  description: 'A vulnerability in a dependency.',
  references: [],
})

// scan_id says which scan a finding belongs to: new and persisting come from
// scan 30, fixed from the baseline. The page uses it to make fixed rows read-only.
const newFinding = finding(1, 'brand new', 'fp-new', 30)
const fixedFinding = finding(2, 'gone now', 'fp-fixed', 20)
const persistingFinding = finding(3, 'still here', 'fp-persisting', 30)
const newerNewFinding = finding(4, 'also new', 'fp-new-2', 30)

const diff = (against: number) => ({
  scan_id: 30,
  against_scan_id: against,
  new: against === 20 ? [newFinding] : [newFinding, newerNewFinding],
  fixed: against === 20 ? [fixedFinding] : [],
  persisting: against === 20 ? [persistingFinding] : [persistingFinding],
  counts: {
    new: against === 20 ? oneCritical : { ...oneCritical, critical: 2 },
    fixed: against === 20 ? oneCritical : emptyCounts,
    persisting: oneCritical,
  },
})

test('compares two scans from the Scans tab (#17)', async ({ page, server }) => {
  const problems = watch(page)
  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [asset] } }),
  )
  await page.route('**/api/scans?**', (route) => {
    const assetId = new URL(route.request().url()).searchParams.get('asset_id')
    const rows =
      assetId === null
        ? scans
        : scans.filter((entry) => entry.asset_id === Number(assetId))
    return route.fulfill({ json: { scans: rows } })
  })
  await page.route('**/api/scans/30', (route) =>
    route.fulfill({ json: scan(30, 'succeeded', oneCritical) }),
  )
  await page.route('**/api/scans/30/diff?**', (route) => {
    const against = new URL(route.request().url()).searchParams.get('against')
    return route.fulfill({ json: diff(against === null ? 20 : Number(against)) })
  })
  await page.route('**/api/scans/30/diff', (route) =>
    route.fulfill({ json: diff(20) }),
  )

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  const origin = new URL(page.url()).origin

  // One Compare link per succeeded scan; the failed scan has none.
  await page.goto(`${origin}/projects?tab=scans`)
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(4)
  await expect(page.getByRole('link', { name: 'Compare' })).toHaveCount(3)
  await expect(
    rows.filter({ hasText: 'failed' }).getByRole('link', { name: 'Compare' }),
  ).toHaveCount(0)

  // The link opens the diff against the previous succeeded scan.
  await rows.first().getByRole('link', { name: 'Compare' }).click()
  await expect(page).toHaveURL(`${origin}/scans/30/diff`)
  await expect(
    page.getByRole('heading', { name: 'Changes in scan #30' }),
  ).toBeVisible()
  await expect(page.getByText('compared with scan #20')).toBeVisible()

  // Three groups, each with its own rows.
  const newRegion = page.getByRole('region', { name: 'New findings' })
  const fixedRegion = page.getByRole('region', { name: 'Fixed findings' })
  const persistingRegion = page.getByRole('region', {
    name: 'Persisting findings',
  })
  await expect(newRegion.locator('tbody tr')).toHaveCount(1)
  await expect(newRegion.getByText('brand new')).toBeVisible()
  await expect(fixedRegion.locator('tbody tr')).toHaveCount(1)
  await expect(fixedRegion.getByText('gone now')).toBeVisible()
  await expect(persistingRegion.locator('tbody tr')).toHaveCount(1)
  await expect(persistingRegion.getByText('still here')).toBeVisible()

  // A fixed finding opens the shared drawer without decision controls.
  await fixedRegion.getByText('gone now').click()
  const drawer = page.getByRole('dialog')
  await expect(drawer).toBeVisible()
  await expect(
    drawer.getByText('This finding is fixed, so there is nothing to decide.'),
  ).toBeVisible()
  await expect(
    drawer.getByRole('heading', { name: 'Decision' }),
  ).toHaveCount(0)
  await drawer.getByRole('button', { name: 'Close' }).click()

  // Compare with another succeeded scan, and the URL keeps the choice.
  await page.locator('#scan-diff-against').selectOption('10')
  await expect(page).toHaveURL(`${origin}/scans/30/diff?against=10`)
  await expect(page.getByText('compared with scan #10')).toBeVisible()
  await expect(newRegion.locator('tbody tr')).toHaveCount(2)
  await expect(fixedRegion.locator('tbody tr')).toHaveCount(0)
  await expect(
    fixedRegion.getByText('No findings were fixed since the scan it is compared with.'),
  ).toBeVisible()

  expect(problems).toEqual([])
})
