import { expect, openConfiguration, test, watch } from './fixtures'

// The interface language (#143) is picked in Configuration → Appearance and
// kept in this browser across reloads.
test('switches the interface to Turkish and keeps it after a reload', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await page.goto(server.url)
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')

  await openConfiguration(page, 'Appearance')
  await page.getByRole('combobox', { name: 'Language' }).selectOption('tr')

  const nav = page.getByRole('navigation')
  await expect(nav.getByRole('link', { name: /^Bulgular/ })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr')

  await page.reload()
  await expect(nav.getByRole('link', { name: /^Bulgular/ })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr')

  expect(problems).toEqual([])
})
