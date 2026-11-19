import { expect, test } from './fixtures'

test('keeps a project scan schedule after a reload', async ({ page, server }) => {
  await page.goto(server.url)
  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible()

  const created = await page.request.post(new URL('/api/assets', server.url).href, {
    headers: { 'X-Bastion': '1' },
    data: { kind: 'path', ref: server.projectDir },
  })
  expect(created.ok()).toBe(true)
  const asset = (await created.json()) as { display_name: string }

  await page.goto(new URL('/repositories', server.url).origin + '/repositories')
  const actions = page.getByRole('button', {
    name: `Actions for ${asset.display_name}`,
  })
  await actions.click()

  // The schedule is a radio group in the row's ⋯ menu, not a select.
  const group = page.getByRole('group', {
    name: `Scan schedule for ${asset.display_name}`,
  })
  const off = group.getByRole('menuitemradio', { name: 'Off' })
  await expect(off).toHaveAttribute('aria-checked', 'true')

  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith('/schedule') && response.request().method() === 'PUT',
  )
  await group.getByRole('menuitemradio', { name: 'Daily' }).click()
  expect((await saved).ok()).toBe(true)

  // A radio choice keeps the menu open, so a second option can be picked
  // without reopening it.
  await expect(actions).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByRole('menu')).toBeVisible()
  await expect(
    group.getByRole('menuitemradio', { name: 'Daily' }),
  ).toHaveAttribute('aria-checked', 'true')

  const resaved = page.waitForResponse(
    (response) =>
      response.url().endsWith('/schedule') && response.request().method() === 'PUT',
  )
  await group.getByRole('menuitemradio', { name: 'Weekly' }).click()
  expect((await resaved).ok()).toBe(true)

  await page.reload()
  await actions.click()
  await expect(
    page
      .getByRole('group', { name: `Scan schedule for ${asset.display_name}` })
      .getByRole('menuitemradio', { name: 'Weekly' }),
  ).toHaveAttribute('aria-checked', 'true')
})
