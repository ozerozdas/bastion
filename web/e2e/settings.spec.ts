import { expect, test, watch } from './fixtures'

/**
 * Settings (#139) is the sidebar's entry above the Local · version footer: it
 * holds the opt-in modules and the global licence policy that used to be cards
 * in the sidebar.
 */
test('opens Settings from the sidebar and closes with Escape', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  // The setting cards are no longer rendered in the sidebar.
  await expect(
    page.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'SAST' })).toHaveCount(0)
  await expect(
    page.getByRole('region', { name: 'Licence policy' }),
  ).toHaveCount(0)

  const opener = page.getByRole('button', { name: 'Settings' })
  await opener.click()

  const dialog = page.getByRole('dialog', { name: 'Settings' })
  await expect(dialog).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'Go reachability' }),
  ).toBeVisible()
  await expect(dialog.getByRole('region', { name: 'SAST' })).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'Licence policy' }),
  ).toBeVisible()

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(opener).toBeFocused()

  expect(problems).toEqual([])
})
