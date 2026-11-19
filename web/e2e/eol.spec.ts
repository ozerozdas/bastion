import { expect, openConfiguration, test, watch } from './fixtures'

test('End-of-life check is off by default and toggles on', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  let on = false
  await page.route('**/api/eol', async (route) => {
    if (route.request().method() === 'PUT') {
      on = (route.request().postDataJSON() as { enabled: boolean }).enabled
    }
    await route.fulfill({ json: { enabled: on } })
  })

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await openConfiguration(page)

  const card = page.getByRole('region', { name: 'End-of-life check' })
  await expect(card.getByText('Off', { exact: true })).toBeVisible()
  await expect(card.getByText(/endoflife\.date/)).toBeVisible()

  const toggle = card.getByRole('switch', { name: 'End-of-life check' })
  await expect(toggle).toHaveAttribute('aria-checked', 'false')
  await toggle.click()
  await expect(card.getByText('On', { exact: true })).toBeVisible()
  await expect(toggle).toHaveAttribute('aria-checked', 'true')

  expect(problems).toEqual([])
})
