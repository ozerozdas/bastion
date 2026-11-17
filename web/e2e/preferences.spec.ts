import { expect, test, watch } from './fixtures'

/**
 * Server preferences (#150) win over the localStorage cache: the cache paints
 * the first frame, then the fetched copy replaces it. This is what makes the
 * choices survive serving bastion on a different port, where localStorage has
 * nothing.
 */
test('a server preference overrides the localStorage cache', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  // Store the copy another origin would have written.
  const status = await page.evaluate(async () => {
    const response = await fetch('/api/preferences', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Bastion': '1' },
      body: JSON.stringify({
        'bastion-theme': 'nord',
        'bastion-mode': 'dark',
      }),
    })
    return response.status
  })
  expect(status).toBe(200)

  // Make this origin's cache stale on purpose.
  await page.evaluate(() => {
    localStorage.setItem('bastion-theme', 'classic')
    localStorage.setItem('bastion-mode', 'light')
  })

  await page.reload()
  // The first paint may use the cache; the server copy wins once it arrives.
  const root = page.locator('html')
  await expect(root).toHaveAttribute('data-theme', 'nord')
  await expect(root).toHaveAttribute('data-mode', 'dark')
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem('bastion-theme')))
    .toBe('nord')

  expect(problems).toEqual([])
})
