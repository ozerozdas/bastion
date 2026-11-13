import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

type DbState = 'missing' | 'downloading' | 'ready'

/**
 * fakeTrivyDBApi serves /api/trivy-db from in-test state. The real cache is
 * empty in every e2e run, so the status starts `missing`; the flow to `ready`
 * is stubbed because the actual download is ~1.7 GB from the network.
 */
async function fakeTrivyDBApi(page: Page) {
  let state: DbState = 'missing'
  let downloads = 0

  const body = () =>
    JSON.stringify({
      state,
      ...(state === 'downloading' ? { trigger: 'user' } : {}),
    })

  await page.route('**/api/trivy-db/download', (route) => {
    downloads += 1
    state = 'downloading'
    return route.fulfill({
      status: 202,
      contentType: 'application/json',
      body: body(),
    })
  })
  await page.route('**/api/trivy-db', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: body() }),
  )

  return {
    downloads: () => downloads,
    finish: () => {
      state = 'ready'
    },
  }
}

test('downloads the vulnerability DB from the sidebar', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const db = await fakeTrivyDBApi(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await expect(
    page.getByText('Vulnerability DB not downloaded', { exact: true }),
  ).toBeVisible()
  // Opening the app only reads the status; nothing downloads until asked.
  expect(db.downloads()).toBe(0)

  await page
    .getByRole('button', {
      name: 'Download vulnerability database (about 1.7 GB)',
    })
    .click()

  const downloading = page.getByRole('status', {
    name: 'Downloading vulnerability database',
  })
  await expect(downloading).toBeVisible()
  await expect(
    downloading.getByText('Downloading vulnerability DB…'),
  ).toBeVisible()

  // The query polls every 2s while the download is in flight.
  db.finish()
  await expect(
    page.getByRole('status', { name: 'Downloading vulnerability database' }),
  ).toHaveCount(0, { timeout: 10_000 })
  await expect(
    page.getByText('Vulnerability DB not downloaded', { exact: true }),
  ).toHaveCount(0)

  expect(db.downloads()).toBe(1)
  expect(problems).toEqual([])
})
