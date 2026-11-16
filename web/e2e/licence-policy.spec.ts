import { expect, openSettings, test, watch } from './fixtures'

// The global licence policy (#39) lives in the settings modal (#139). This test
// edits it through the real server, so the PUT, the normalization and the
// reloaded GET are all exercised.
test('edits the global licence policy', async ({ page, server }) => {
  const problems = watch(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await openSettings(page)

  const card = page.getByRole('region', { name: 'Licence policy' })
  await expect(card).toBeVisible()
  await expect(
    card.getByText('No rules. Licences are reported as scanned.'),
  ).toBeVisible()

  await card.getByRole('button', { name: 'Edit' }).click()
  await card.getByLabel('Allowed licences').fill('MIT\nApache-2.0')
  await card.getByLabel('Denied licences').fill('GPL-3.0')
  await card.getByRole('button', { name: 'Save licence policy' }).click()

  await expect(card.getByText('2 allowed · 1 denied')).toBeVisible()

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // The policy is stored, not just local state.
  await page.reload()
  await openSettings(page)
  const reloaded = page.getByRole('region', { name: 'Licence policy' })
  await expect(reloaded.getByText('2 allowed · 1 denied')).toBeVisible()

  expect(problems).toEqual([])
})
