import type { Page } from '@playwright/test'

import { expect, stubLicencePolicy, test, watch } from './fixtures'

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


/** StubFinding is the subset of a Finding the stubbed API needs. */
type StubFinding = {
  id: number
  scan_id: number
  asset_id: number
  type: string
  fingerprint: string
  severity: string
  title: string
  rule_id?: string
  package_name?: string
  package_version?: string
  fixed_version?: string
  location?: string
  occurrences: number
  scanner: string
  status: string
  description?: string
  references: string[]
}

/** StubGroup mirrors the API's FindingGroup, built the way the server does. */
type StubGroup = {
  key: string
  rule_id?: string
  title: string
  type: string
  severity: string
  asset_ids: number[]
  project_count: number
  packages: string[]
  fixed_versions: string[]
  fixed_version?: string
  findings: StubFinding[]
}

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
}

function rank(severity: string): number {
  return severityRank[severity] ?? severityRank.unknown
}

/** groupRows folds one row per rule and type, like reports.GroupFindings. */
function groupRows(rows: StubFinding[]): StubGroup[] {
  const groups = new Map<string, StubGroup>()
  for (const finding of rows) {
    const ruleId = finding.rule_id?.trim() ?? ''
    const key = `${ruleId === '' ? finding.fingerprint : ruleId}\u0000${finding.type}`
    let group = groups.get(key)
    if (group === undefined) {
      group = {
        key,
        rule_id: ruleId === '' ? undefined : ruleId,
        title: finding.title,
        type: finding.type,
        severity: finding.severity,
        asset_ids: [],
        project_count: 0,
        packages: [],
        fixed_versions: [],
        findings: [],
      }
      groups.set(key, group)
    }
    group.findings.push(finding)
    if (!group.asset_ids.includes(finding.asset_id)) {
      group.asset_ids.push(finding.asset_id)
    }
    const packageName = finding.package_name?.trim() ?? ''
    if (packageName !== '' && !group.packages.includes(packageName)) {
      group.packages.push(packageName)
    }
    const fixed = finding.fixed_version ?? ''
    if (fixed !== '' && !group.fixed_versions.includes(fixed)) {
      group.fixed_versions.push(fixed)
    }
    if (rank(finding.severity) < rank(group.severity)) {
      group.severity = finding.severity
    }
  }

  const ordered = [...groups.values()]
  for (const group of ordered) {
    group.project_count = group.asset_ids.length
    if (group.fixed_versions.length === 1) {
      group.fixed_version = group.fixed_versions[0]
    }
  }
  return ordered.sort(
    (a, b) =>
      rank(a.severity) - rank(b.severity) ||
      b.findings.length - a.findings.length ||
      a.title.localeCompare(b.title),
  )
}

/**
 * respondFindings answers GET /api/findings the way the server does: filter,
 * pick the view, then cut the page and report both totals.
 */
function respondFindings(rows: StubFinding[], url: URL) {
  const assetId = url.searchParams.get('asset_id')
  const severity = url.searchParams.get('severity')
  const type = url.searchParams.get('type')
  const status = url.searchParams.get('status')
  const q = url.searchParams.get('q')?.toLowerCase() ?? ''
  const filtered = rows.filter(
    (finding) =>
      (assetId === null || finding.asset_id === Number(assetId)) &&
      (severity === null || finding.severity === severity) &&
      (type === null || finding.type === type) &&
      (status === null || finding.status === status) &&
      (q === '' ||
        [finding.title, finding.rule_id, finding.package_name, finding.location].some(
          (value) => (value ?? '').toLowerCase().includes(q),
        )),
  )
  const view = url.searchParams.get('view') ?? 'single'
  const limit = Number(url.searchParams.get('limit') ?? '50')
  const offset = Number(url.searchParams.get('offset') ?? '0')
  const window = <T>(items: T[]): T[] => items.slice(offset, offset + limit)

  if (view === 'grouped') {
    const groups = groupRows(filtered)
    return {
      json: {
        findings: [],
        groups: window(groups),
        total: groups.length,
        total_findings: filtered.length,
        limit,
        offset,
      },
    }
  }
  return {
    json: {
      findings: window(filtered),
      groups: [],
      total: filtered.length,
      total_findings: filtered.length,
      limit,
      offset,
    },
  }
}

const findings: StubFinding[] = [
  {
    ...baseFinding,
    rule_id: 'CVE-2021-1111',
    id: 1,
    asset_id: beta.id,
    fingerprint: 'fp-beta-critical',
    severity: 'critical',
    title: 'Critical in beta',
  },
  {
    ...baseFinding,
    rule_id: 'CVE-2022-2222',
    id: 2,
    asset_id: alpha.id,
    fingerprint: 'fp-alpha-high',
    severity: 'high',
    title: 'High in alpha',
  },
  {
    ...baseFinding,
    rule_id: 'CVE-2023-3333',
    id: 3,
    asset_id: beta.id,
    fingerprint: 'fp-beta-medium',
    severity: 'medium',
    title: 'Medium in beta',
  },
  // One CVE in both projects: grouped mode folds the pair into a single row.
  {
    ...baseFinding,
    rule_id: 'CVE-2024-4444',
    id: 4,
    asset_id: alpha.id,
    fingerprint: 'fp-alpha-shared',
    severity: 'high',
    title: 'Shared vulnerability',
  },
  {
    ...baseFinding,
    rule_id: 'CVE-2024-4444',
    id: 5,
    asset_id: beta.id,
    fingerprint: 'fp-beta-shared',
    severity: 'high',
    title: 'Shared vulnerability',
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
  await stubLicencePolicy(page)
  const problems = watch(page)
  const requested: URL[] = []

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) => {
    const url = new URL(route.request().url())
    requested.push(url)
    return route.fulfill(respondFindings(findings, url))
  })

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()

  await expect(page.locator('#page-heading')).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'Project' })).toBeVisible()
  await expect(page.locator('#findings-project')).toHaveValue('')

  const origin = new URL(page.url()).origin
  // Grouped is the default, so a fresh visit has no view param and folds the
  // five findings into four rules (#106).
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.getByRole('button', { name: 'Grouped' })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(4)

  // Single is the opt-out and stays in the URL.
  await page.getByRole('button', { name: 'Single' }).click()
  await expect(page).toHaveURL(`${origin}/findings?view=single`)
  await expect(rows).toHaveCount(5)
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

  // The Project filter narrows the same list to one project and forces single,
  // so the view toggle is not offered any more.
  requested.length = 0
  await page.locator('#findings-project').selectOption(String(beta.id))
  await expect(rows).toHaveCount(3)
  await expect(rows.nth(0)).toContainText('beta')
  await expect(page).toHaveURL(`${origin}/findings/${String(beta.id)}`)
  await expect(page.getByRole('group', { name: 'Findings view' })).toHaveCount(0)
  expect(requested.at(-1)?.searchParams.get('asset_id')).toBe(String(beta.id))

  // Back to every project, which returns to the grouped default.
  await page.locator('#findings-project').selectOption('')
  await expect(rows).toHaveCount(4)
  await expect(page).toHaveURL(`${origin}/findings`)

  expect(problems).toEqual([])
})

test('opens a finding and follows it to its project', async ({
  page,
  server,
}) => {
  await stubLicencePolicy(page)
  const problems = watch(page)

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings(findings, new URL(route.request().url()))),
  )

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()
  // One row per finding, so the row opens the finding's own drawer.
  await page.getByRole('button', { name: 'Single' }).click()

  await page.getByRole('row', { name: /High in alpha/ }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  // The drawer names the project the finding belongs to and links to it.
  await expect(dialog.getByText('Project', { exact: true })).toBeVisible()

  const origin = new URL(page.url()).origin
  await dialog.getByRole('link', { name: 'alpha', exact: true }).click()
  await expect(page).toHaveURL(`${origin}/findings/${String(alpha.id)}`)
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.locator('#findings-project')).toHaveValue(String(alpha.id))

  expect(problems).toEqual([])
})

test('groups one CVE across projects and keeps the view in the URL', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings(findings, new URL(route.request().url()))),
  )

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()
  const origin = new URL(page.url()).origin

  // Grouped is the default, so the fleet-wide list opens grouped (#106).
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.getByRole('button', { name: 'Grouped' })).toHaveAttribute(
    'aria-pressed',
    'true',
  )

  const rows = page.locator('tbody tr')
  // Three single-project rules plus the CVE alpha and beta share.
  await expect(rows).toHaveCount(4)
  const shared = rows.filter({ hasText: 'CVE-2024-4444' })
  await expect(shared).toHaveCount(1)
  await expect(shared).toContainText('Shared vulnerability')
  await expect(shared).toContainText('2 projects')
  await expect(shared).toContainText('4.17.21')

  // A reload stays grouped: the bare URL is the grouped default.
  await page.reload()
  await expect(page.locator('#page-heading')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Grouped' })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  await expect(page.locator('tbody tr')).toHaveCount(4)

  // The drawer lists every affected project with installed and fixed version.
  await page.locator('tbody tr').filter({ hasText: 'CVE-2024-4444' }).click()
  const drawer = page.getByRole('dialog')
  await expect(
    drawer.getByRole('heading', { name: 'Shared vulnerability' }),
  ).toBeVisible()
  await expect(drawer.getByRole('button', { name: /alpha/ })).toContainText(
    'lodash@4.17.0',
  )
  await expect(drawer.getByRole('button', { name: /beta/ })).toContainText(
    'lodash@4.17.0',
  )
  await expect(drawer.getByRole('button', { name: /beta/ })).toContainText('4.17.21')

  // Opening one project's finding swaps the drawer; closing it gives focus
  // back to the grouped row, not to the page body.
  await drawer.getByRole('button', { name: /alpha/ }).click()
  await expect(page.getByRole('dialog')).toHaveCount(1)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(
    page.locator('tbody tr').filter({ hasText: 'CVE-2024-4444' }),
  ).toBeFocused()

  // Single is one row per finding, and opting out is in the URL; grouped is
  // the bare path again.
  await page.getByRole('button', { name: 'Single' }).click()
  await expect(page).toHaveURL(`${origin}/findings?view=single`)
  await expect(page.locator('tbody tr')).toHaveCount(5)

  await page.getByRole('button', { name: 'Grouped' }).click()
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.locator('tbody tr')).toHaveCount(4)

  expect(problems).toEqual([])
})

test('redirects old report URLs to the findings list', async ({ page, server }) => {
  await stubLicencePolicy(page)
  const problems = watch(page)
  const asset = { ...alpha, id: 42, display_name: 'forty-two' }

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [asset] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings([], new URL(route.request().url()))),
  )

  await openDashboard(page, server.url)
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/reports?asset=${String(asset.id)}`)
  await expect(page).toHaveURL(`${origin}/findings/${String(asset.id)}`)
  await expect(page.locator('#page-heading')).toBeVisible()
  await expect(page.locator('#findings-project')).toHaveValue(String(asset.id))

  await page.goto(`${origin}/reports`)
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.locator('#findings-project')).toHaveValue('')

  // The name the previous UI used keeps working too.
  await page.goto(`${origin}/security-reports?asset=${String(asset.id)}`)
  await expect(page).toHaveURL(`${origin}/findings/${String(asset.id)}`)

  expect(problems).toEqual([])
})

test('a bulk decision sends one request per project', async ({ page, server }) => {
  const problems = watch(page)
  const requests: {
    asset_id: number
    fingerprints: string[]
    state: string
    reason: string
  }[] = []

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings(findings, new URL(route.request().url()))),
  )
  // The bulk endpoint takes one asset per request; a per-finding POST would
  // match neither this route nor the list stub and fail the test.
  await page.route('**/api/findings/state', (route) => {
    requests.push(route.request().postDataJSON() as (typeof requests)[number])
    return route.fulfill({ status: 204 })
  })

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()

  // Grouped is the default, and a group stands for every member finding, so
  // selecting all groups covers findings in both projects.
  await page.getByLabel('Select all grouped findings').check()
  await expect(page.getByText('5 selected')).toBeVisible()

  await page.getByRole('textbox', { name: 'Reason' }).fill('shared reason')
  await page.getByRole('button', { name: 'Hide 5' }).click()

  await expect.poll(() => requests.length).toBe(2)
  const byAsset = new Map(requests.map((body) => [body.asset_id, body]))
  expect(byAsset.size).toBe(2)

  const betaBody = byAsset.get(beta.id)
  expect(betaBody?.state).toBe('ignored')
  expect(betaBody?.reason).toBe('shared reason')
  expect(betaBody?.fingerprints.toSorted()).toEqual(
    ['fp-beta-critical', 'fp-beta-medium', 'fp-beta-shared'].toSorted(),
  )

  const alphaBody = byAsset.get(alpha.id)
  expect(alphaBody?.state).toBe('ignored')
  expect(alphaBody?.fingerprints.toSorted()).toEqual(
    ['fp-alpha-high', 'fp-alpha-shared'].toSorted(),
  )

  // The selection clears once the decision is stored.
  await expect(page.getByText('5 selected')).toHaveCount(0)
  expect(problems).toEqual([])
})

test('exports the current view as a download from the page actions', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings(findings, new URL(route.request().url()))),
  )

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()

  // The link carries the current view and filters; the download is the real
  // endpoint's, so the filename is its own too.
  await page.getByRole('button', { name: 'Export' }).click()
  const groupedHref = await page
    .getByRole('menuitem', { name: 'CSV' })
    .getAttribute('href')
  const groupedUrl = new URL(groupedHref ?? '', 'http://localhost')
  expect(groupedUrl.pathname).toBe('/api/findings/export')
  expect(groupedUrl.searchParams.get('view')).toBe('grouped')
  expect(groupedUrl.searchParams.get('status')).toBe('open')
  expect(groupedUrl.searchParams.get('format')).toBe('csv')

  const groupedDownload = page.waitForEvent('download')
  await page.getByRole('menuitem', { name: 'CSV' }).click()
  expect((await groupedDownload).suggestedFilename()).toMatch(
    /^bastion-findings-grouped-\d{8}\.csv$/,
  )

  // The menu follows the view: single exports one row per finding.
  await page.getByRole('button', { name: 'Single' }).click()
  await page.getByRole('button', { name: 'Export' }).click()
  const singleHref = await page
    .getByRole('menuitem', { name: 'CSV' })
    .getAttribute('href')
  expect(new URL(singleHref ?? '', 'http://localhost').searchParams.get('view')).toBe(
    'single',
  )

  const singleDownload = page.waitForEvent('download')
  await page.getByRole('menuitem', { name: 'CSV' }).click()
  expect((await singleDownload).suggestedFilename()).toMatch(
    /^bastion-findings-single-\d{8}\.csv$/,
  )

  expect(problems).toEqual([])
})

test('pages findings server-side and keeps the page in the URL', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const paged: StubFinding[] = Array.from({ length: 120 }, (_, index) => ({
    ...baseFinding,
    id: 1000 + index,
    asset_id: index % 2 === 0 ? alpha.id : beta.id,
    fingerprint: `fp-paged-${String(index)}`,
    rule_id: `CVE-2030-${String(index).padStart(4, '0')}`,
    severity: index % 2 === 0 ? 'high' : 'medium',
    title: `Paged finding ${String(index)}`,
  }))

  await page.route('**/api/assets', (route) =>
    route.fulfill({ json: { assets: [alpha, beta] } }),
  )
  await page.route('**/api/findings?**', (route) =>
    route.fulfill(respondFindings(paged, new URL(route.request().url()))),
  )

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()
  const origin = new URL(page.url()).origin
  const pager = page.getByRole('navigation', { name: 'Pagination' })
  const rows = page.locator('tbody tr')

  // Grouped is the default; the footer states the window and the total.
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(rows).toHaveCount(50)
  await expect(pager).toContainText('1–50 of 120')

  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(`${origin}/findings?page=2`)
  await expect(rows).toHaveCount(50)
  await expect(pager).toContainText('51–100 of 120')

  // Select-all covers the current page only.
  await page.getByLabel('Select all grouped findings').check()
  await expect(page.getByText('50 selected')).toBeVisible()

  // Jumping to the last page clears the selection and shows the short page.
  await page.locator('#pager-page').fill('3')
  await page.locator('#pager-page').press('Enter')
  await expect(page).toHaveURL(`${origin}/findings?page=3`)
  await expect(rows).toHaveCount(20)
  await expect(pager).toContainText('101–120 of 120')
  await expect(page.getByText('50 selected')).toHaveCount(0)

  // A page size goes back to page 1 and stays in the URL.
  await page.getByLabel('Rows per page').selectOption('25')
  await expect(page).toHaveURL(`${origin}/findings?size=25`)
  await expect(rows).toHaveCount(25)
  await expect(pager).toContainText('1–25 of 120')

  // A filter change also resets the page; 60 of the 120 findings are high.
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(`${origin}/findings?size=25&page=2`)
  await page.locator('#findings-severity').selectOption('high')
  await expect(page).toHaveURL(`${origin}/findings?size=25`)
  await expect(pager).toContainText('1–25 of 60')

  expect(problems).toEqual([])
})

test('searches findings by text and keeps the search in the URL', async ({
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
    return route.fulfill(respondFindings(findings, url))
  })

  await openDashboard(page, server.url)
  await page.getByRole('link', { name: /^Findings/ }).click()
  const origin = new URL(page.url()).origin
  const rows = page.locator('tbody tr')

  // The search settles into ?q= after the debounce and narrows the list.
  await page.getByRole('searchbox', { name: 'Search' }).fill('CVE-2022')
  await expect(page).toHaveURL(`${origin}/findings?q=CVE-2022`)
  await expect(rows).toHaveCount(1)
  await expect(rows.nth(0)).toContainText('High in alpha')
  expect(requested.at(-1)?.searchParams.get('q')).toBe('CVE-2022')

  // Another filter keeps the search: only the search is in the URL, so it
  // survives a severity change and the page resets.
  await page.locator('#findings-severity').selectOption('high')
  await expect(page).toHaveURL(`${origin}/findings?q=CVE-2022`)
  await expect(rows).toHaveCount(1)

  // Clearing it drops the param and restores the severity-filtered groups.
  await page.getByRole('searchbox', { name: 'Search' }).fill('')
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(rows).toHaveCount(2)

  expect(problems).toEqual([])
})
