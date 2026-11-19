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

  // One card opens its report; the report keeps the project scope. Reports
  // without a panel yet still explain that they are on the way.
  await page.getByRole('link', { name: /Licenses & SBOM/ }).click()
  await expect(page).toHaveURL(`${origin}/reports/licenses-sbom`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Licenses & SBOM' }),
  ).toBeVisible()
  await expect(page.getByText('Coming soon', { exact: true })).toBeVisible()

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
