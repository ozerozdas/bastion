import { expect, test, watch } from './fixtures'

/**
 * Configuration (#139, #142) is the sidebar's SETTINGS entry, next to
 * Connections: a page with the opt-in modules, the policies and the appearance
 * preferences that used to be cards in the sidebar.
 */
test('opens Configuration from the sidebar and follows its tabs', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  // No LLM server runs in e2e; stub the model list the AI tab asks for.
  await page.route('**/api/llm/models*', (route) =>
    route.fulfill({ json: { models: ['llama3.1', 'qwen3:14b'] } }),
  )

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

  // One nav link under SETTINGS, not a modal opener.
  const opener = page
    .getByRole('group', { name: 'SETTINGS' })
    .getByRole('link', { name: 'Configuration' })
  await expect(opener).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Settings', exact: true }),
  ).toHaveCount(0)
  await opener.click()

  const origin = new URL(page.url()).origin
  await expect(page).toHaveURL(`${origin}/configurations`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Configuration' }),
  ).toBeVisible()
  // The page is not a modal any more.
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // Modules is the first tab and holds the current on/off settings.
  const modulesTab = page.getByRole('tab', { name: 'Modules', exact: true })
  const appearanceTab = page.getByRole('tab', {
    name: 'Appearance',
    exact: true,
  })
  await expect(modulesTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toBeVisible()
  await expect(
    page.getByRole('region', { name: 'Go reachability' }),
  ).toBeVisible()
  await expect(
    page.getByRole('region', { name: 'Outdated packages' }),
  ).toBeVisible()
  await expect(page.getByRole('region', { name: 'SAST' })).toBeVisible()
  await expect(
    page.getByRole('region', { name: 'End-of-life check' }),
  ).toBeVisible()
  // The licence policy is a policy now, so it lives on its own tab.
  await expect(
    page.getByRole('region', { name: 'Licence policy' }),
  ).toHaveCount(0)

  // The tabs follow the WAI-ARIA pattern the page tabs use.
  await modulesTab.focus()
  await page.keyboard.press('ArrowRight')
  await expect(
    page.getByRole('tab', { name: 'Policies', exact: true }),
  ).toBeFocused()
  await expect(
    page.getByRole('tab', { name: 'Policies', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByRole('region', { name: 'Licence policy' }),
  ).toBeVisible()
  await page.keyboard.press('ArrowRight')
  await expect(
    page.getByRole('tab', { name: 'Notifications', exact: true }),
  ).toBeFocused()
  await page.keyboard.press('ArrowRight')
  await expect(
    page.getByRole('tab', { name: 'AI', exact: true }),
  ).toBeFocused()
  await expect(
    page.getByRole('tab', { name: 'AI', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByLabel('Endpoint')).toBeVisible()
  await expect(page.locator('#ai-models option')).toHaveCount(2)
  await page.keyboard.press('ArrowRight')
  await expect(
    page.getByRole('tab', { name: 'MCP', exact: true }),
  ).toBeFocused()
  await expect(
    page.getByRole('tab', { name: 'MCP', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  // The default client is Claude Code and names the running binary.
  await expect(page.getByText(/mcp --data-dir/)).toBeVisible()
  await page.keyboard.press('ArrowRight')
  await expect(appearanceTab).toBeFocused()
  await expect(appearanceTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByRole('region', { name: 'EPSS exploit scores' }),
  ).toHaveCount(0)
  await expect(page.getByRole('group', { name: 'Font size' })).toBeVisible()
  // The chosen tab is in the URL, so a reload lands on it.
  await expect(page).toHaveURL(`${origin}/configurations?tab=appearance`)

  // Leaving the page with the sidebar is a normal navigation.
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

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

  await page.getByRole('link', { name: 'Configuration', exact: true }).click()
  await page
    .getByRole('tab', { name: 'Appearance', exact: true })
    .click()

  // The swatch cards are radios, so the palette is one named group. The input
  // itself is visually hidden; clicking the card's label is the user's path.
  const nord = page.getByRole('radio', { name: /Nord-style/ })
  await page.getByText('Nord-style', { exact: true }).click()
  await expect(nord).toBeChecked()
  await page
    .getByRole('group', { name: 'Font size' })
    .getByRole('button', { name: 'Large', exact: true })
    .click()
  await page
    .getByRole('group', { name: 'Colour mode' })
    .getByRole('button', { name: 'Dark', exact: true })
    .click()

  // Applied live, without leaving the page.
  const root = page.locator('html')
  await expect(root).toHaveAttribute('data-theme', 'nord')
  await expect(root).toHaveAttribute('data-mode', 'dark')
  const liveSize = await page.evaluate(() =>
    getComputedStyle(document.documentElement).fontSize,
  )
  expect(liveSize).toBe('18px')

  await page.reload()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Configuration' }),
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
