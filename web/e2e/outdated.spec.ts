import type { Page } from '@playwright/test'

import { expect, openConfiguration, test, watch } from './fixtures'

/**
 * stubOutdated answers /api/outdated from in-page state. `enabled` starts off,
 * so the default page proves the off setting renders no latest-version data,
 * and the server never reaches deps.dev.
 */
async function stubOutdated(page: Page, enabled = false) {
  let on = enabled
  await page.route('**/api/outdated', async (route) => {
    if (route.request().method() === 'PUT') {
      const { enabled: next } = route.request().postDataJSON() as { enabled: boolean }
      on = next
    }
    await route.fulfill({ json: { enabled: on } })
  })
}

test('Outdated packages is off by default and toggles on', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await stubOutdated(page, false)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await openConfiguration(page)

  const card = page.getByRole('region', { name: 'Outdated packages' })
  await expect(card).toBeVisible()
  await expect(card.getByText('Off', { exact: true })).toBeVisible()
  await expect(
    card.getByText(/api\.deps\.dev/),
  ).toBeVisible()

  const toggle = card.getByRole('switch', { name: 'Outdated packages' })
  await expect(toggle).toHaveAttribute('aria-checked', 'false')
  await toggle.click()

  await expect(card.getByText('On', { exact: true })).toBeVisible()
  await expect(toggle).toHaveAttribute('aria-checked', 'true')

  // Leaving the page with the sidebar keeps the saved choice: no modal lingers.
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)

  expect(problems).toEqual([])
})
