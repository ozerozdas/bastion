import type { Page } from '@playwright/test'

import { expect, openSettings, test, watch } from './fixtures'

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
  await openSettings(page)

  const card = page.getByRole('region', { name: 'Outdated packages' })
  await expect(card).toBeVisible()
  await expect(card.getByText('Off', { exact: true })).toBeVisible()
  await expect(
    card.getByText(/api\.deps\.dev/),
  ).toBeVisible()

  await card.getByRole('button', { name: 'Turn on Outdated packages' }).click()

  await expect(card.getByText('On', { exact: true })).toBeVisible()
  await expect(
    card.getByRole('button', { name: 'Turn off Outdated packages' }),
  ).toBeVisible()

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  expect(problems).toEqual([])
})
