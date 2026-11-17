import { expect, test, watch } from './fixtures'

/**
 * Configuration (#139, #142) is the sidebar's SETTINGS entry, next to
 * Connections: a tabbed modal holding the opt-in modules and the appearance
 * preferences that used to be cards in the sidebar.
 */
test('opens Configuration from the sidebar and closes with Escape', async ({
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

  // One nav entry under SETTINGS, not the old standalone button.
  const opener = page
    .getByRole('group', { name: 'SETTINGS' })
    .getByRole('button', { name: 'Configuration' })
  await expect(opener).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Settings', exact: true }),
  ).toHaveCount(0)
  await opener.click()

  const dialog = page.getByRole('dialog', { name: 'Configuration' })
  await expect(dialog).toBeVisible()

  // Modules is the first tab and holds the current on/off settings.
  const modulesTab = dialog.getByRole('tab', { name: 'Modules', exact: true })
  const appearanceTab = dialog.getByRole('tab', {
    name: 'Appearance',
    exact: true,
  })
  await expect(modulesTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    dialog.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'Go reachability' }),
  ).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'Outdated packages' }),
  ).toBeVisible()
  await expect(dialog.getByRole('region', { name: 'SAST' })).toBeVisible()
  await expect(
    dialog.getByRole('region', { name: 'Licence policy' }),
  ).toBeVisible()

  // The tabs follow the WAI-ARIA pattern the page tabs use.
  await modulesTab.focus()
  await page.keyboard.press('ArrowRight')
  await expect(
    dialog.getByRole('tab', { name: 'Notifications', exact: true }),
  ).toBeFocused()
  await page.keyboard.press('ArrowRight')
  await expect(appearanceTab).toBeFocused()
  await expect(appearanceTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    dialog.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toHaveCount(0)
  await expect(dialog.getByRole('group', { name: 'Font size' })).toBeVisible()

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(opener).toBeFocused()

  expect(problems).toEqual([])
})

test('keeps the chosen theme and font size after a reload', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await page.getByRole('button', { name: 'Configuration' }).click()
  const dialog = page.getByRole('dialog', { name: 'Configuration' })
  await dialog.getByRole('tab', { name: 'Appearance', exact: true }).click()

  // The swatch cards are radios, so the palette is one named group. The input
  // itself is visually hidden; clicking the card's label is the user's path.
  const nord = dialog.getByRole('radio', { name: /Nord-style/ })
  await dialog.getByText('Nord-style', { exact: true }).click()
  await expect(nord).toBeChecked()
  await dialog
    .getByRole('group', { name: 'Font size' })
    .getByRole('button', { name: 'Large', exact: true })
    .click()
  await dialog
    .getByRole('group', { name: 'Colour mode' })
    .getByRole('button', { name: 'Dark', exact: true })
    .click()

  // Applied live, without closing the dialog.
  const root = page.locator('html')
  await expect(root).toHaveAttribute('data-theme', 'nord')
  await expect(root).toHaveAttribute('data-mode', 'dark')
  const liveSize = await page.evaluate(() =>
    getComputedStyle(document.documentElement).fontSize,
  )
  expect(liveSize).toBe('18px')

  await page.reload()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  // The preferences are read before the first render and applied again.
  await expect(root).toHaveAttribute('data-theme', 'nord')
  await expect(root).toHaveAttribute('data-mode', 'dark')
  await expect
    .poll(() =>
      page.evaluate(() => getComputedStyle(document.documentElement).fontSize),
    )
    .toBe('18px')

  // The quick toggle flips the mode inside the same theme family.
  await page.getByRole('button', { name: 'Switch to light theme' }).click()
  await expect(root).toHaveAttribute('data-theme', 'nord')
  await expect(root).toHaveAttribute('data-mode', 'light')

  expect(problems).toEqual([])
})
