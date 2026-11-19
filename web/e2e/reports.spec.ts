import { expect, test, watch } from './fixtures'

/**
 * Reports (#190) is the card grid under Settings & More: every card opens its
 * own page, and the band carries the project switcher.
 */
test('opens Reports from the sidebar and one of its reports', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await page
    .getByRole('group', { name: 'SETTINGS & MORE' })
    .getByRole('link', { name: 'Reports', exact: true })
    .click()

  const origin = new URL(page.url()).origin
  await expect(page).toHaveURL(`${origin}/reports`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Reports' }),
  ).toBeVisible()
  // The band's project switcher starts on every project.
  await expect(page.locator('#findings-project')).toHaveValue('')

  const cards = page.getByRole('list', { name: 'Reports' }).getByRole('listitem')
  await expect(cards).toHaveCount(9)

  // One card opens its report; the report keeps the project scope.
  await page.getByRole('link', { name: /Licenses & SBOM/ }).click()
  await expect(page).toHaveURL(`${origin}/reports/licenses-sbom`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Licenses & SBOM' }),
  ).toBeVisible()
  await expect(page.getByText('No licences recorded')).toBeVisible()

  expect(problems).toEqual([])
})

/**
 * The implemented reports open on an empty database and show their own empty
 * state: no chart data is not an error, and neither is an empty OWASP mapping.
 */
test('renders the trend and OWASP Top 10 reports', async ({ page, server }) => {
  const problems = watch(page)
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/reports/trend`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Trend over time' }),
  ).toBeVisible()
  await expect(page.getByText('No scan history yet')).toBeVisible()

  await page.goto(`${origin}/reports/owasp-top10`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'OWASP Top 10' }),
  ).toBeVisible()
  await expect(page.getByText('Nothing mapped yet')).toBeVisible()

  expect(problems).toEqual([])
})

/**
 * The SLA report writes the same thresholds Configuration reads: a saved
 * value survives a reload. The printable audit and the CI history render on an
 * empty database too, with their own empty states.
 */
test('saves SLA thresholds and renders the audit and CI history reports', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/reports/sla`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'SLA insights' }),
  ).toBeVisible()
  await expect(page.getByText('Nothing overdue')).toBeVisible()

  const critical = page.getByLabel('Critical', { exact: true })
  await critical.fill('45')
  await page.getByRole('button', { name: 'Save thresholds' }).click()
  await expect(page.getByRole('status')).toHaveText('Saved')

  await page.reload()
  await expect(page.getByLabel('Critical', { exact: true })).toHaveValue('45')

  await page.goto(`${origin}/reports/audit`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Security audit' }),
  ).toBeVisible()
  await expect(page.getByText('Bastion Security Audit')).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Print / Save as PDF' }),
  ).toBeVisible()
  await expect(page.getByText('No findings to audit')).toBeVisible()

  await page.goto(`${origin}/reports/ci-history`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'CI scan history' }),
  ).toBeVisible()
  await expect(page.getByText('No CI runs yet')).toBeVisible()

  expect(problems).toEqual([])
})
