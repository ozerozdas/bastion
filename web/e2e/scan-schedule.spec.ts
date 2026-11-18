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
  const schedule = page.getByRole('combobox', {
    name: `Scan schedule for ${asset.display_name}`,
  })
  await expect(schedule).toHaveValue('off')

  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith('/schedule') && response.request().method() === 'PUT',
  )
  await schedule.selectOption('daily')
  expect((await saved).ok()).toBe(true)

  await page.reload()
  await expect(schedule).toHaveValue('daily')
})
