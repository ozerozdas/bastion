import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

const localImages = [
  {
    reference: 'alpine:3.20',
    id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    size_bytes: 8 * 1024 * 1024,
    created_at: '2026-11-01T10:00:00Z',
  },
  {
    reference: 'nginx:latest',
    id: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    size_bytes: 200 * 1024 * 1024,
    created_at: '2026-11-10T10:00:00Z',
  },
]

const dockerHost = 'unix:///var/run/docker.sock'

/** fakeDockerApi serves the daemon probe from in-test state. */
async function fakeDockerApi(page: Page, available: boolean) {
  await page.route('**/api/docker/images', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        available,
        host: available ? dockerHost : '',
        images: available ? localImages : [],
      }),
    }),
  )
}

/** fakeAssetsApi serves the asset list and the create response. */
async function fakeAssetsApi(
  page: Page,
  assets: unknown[],
  created: unknown = null,
) {
  await page.route('**/api/assets', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ assets }),
      })
    }
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify(created),
    })
  })
}

const alpineAsset = {
  id: 7,
  kind: 'image',
  display_name: 'alpine:3.20',
  ref: 'alpine:3.20',
  created_at: '2026-11-14T10:00:00Z',
  last_scan: {
    scan_id: 11,
    status: 'succeeded',
    finished_at: '2026-11-14T10:05:00Z',
  },
  open_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
}

test('Connections shows a Docker status card and links to Containers', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page, true)
  await fakeAssetsApi(page, [], alpineAsset)

  await page.route('**/api/scans', (route) => {
    return route.fulfill({
      status: 202,
      contentType: 'application/json',
      body: JSON.stringify({ scans: [{ scan_id: 11, asset_id: 7 }] }),
    })
  })

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Connections', exact: true }).click()
  await page.getByRole('tab', { name: 'Registry' }).click()

  // The card is status only: badge, reached host, image count, link out.
  await expect(page.getByRole('heading', { name: 'Docker' })).toBeVisible()
  await expect(page.getByText(dockerHost, { exact: true })).toBeVisible()
  await expect(page.getByText('2 images', { exact: true })).toBeVisible()

  const assetRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets') && request.method() === 'POST',
  )
  const scanRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/scans') && request.method() === 'POST',
  )

  await page.getByRole('link', { name: 'View containers' }).click()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Containers' }),
  ).toBeVisible()
  await expect(page.getByText('alpine:3.20', { exact: true })).toBeVisible()
  await expect(page.getByText('nginx:latest', { exact: true })).toBeVisible()

  await page
    .getByRole('row')
    .filter({ hasText: 'alpine:3.20' })
    .getByRole('button', { name: 'Scan' })
    .click()

  expect((await assetRequest).postDataJSON()).toEqual({
    kind: 'image',
    ref: 'alpine:3.20',
  })
  expect((await scanRequest).postDataJSON()).toEqual({ asset_ids: [7] })
  expect(problems).toEqual([])
})

test('Containers shows a tracked image scan and its findings link', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page, true)
  await fakeAssetsApi(page, [alpineAsset])

  await page.goto(server.url)
  // Image assets stay off the Repositories page and out of its count.
  await page.getByRole('link', { name: 'Repositories', exact: true }).click()
  await expect(
    page.getByRole('heading', { name: 'No repositories yet' }),
  ).toBeVisible()

  // The badge counts tracked image assets, not local daemon images.
  await page.getByRole('link', { name: 'Containers, 1' }).click()

  const row = page.getByRole('row').filter({ hasText: 'alpine:3.20' })
  await expect(row.getByText('succeeded', { exact: true })).toBeVisible()
  await expect(row.getByLabel('1 open critical findings')).toBeVisible()
  await expect(row.getByRole('link', { name: 'View findings' })).toHaveAttribute(
    'href',
    '/findings?asset=7',
  )
  expect(problems).toEqual([])
})

test('Containers explains when no Docker daemon is available', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page, false)

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers', exact: true }).click()

  await expect(
    page.getByRole('heading', { name: 'No Docker daemon found' }),
  ).toBeVisible()
  await expect(
    page.getByText(/Start Docker, OrbStack or Colima/),
  ).toBeVisible()

  // Connections still hides its Docker card, and AWS stays.
  await page.getByRole('link', { name: 'Connections', exact: true }).click()
  await page.getByRole('tab', { name: 'Registry' }).click()
  await expect(page.getByRole('heading', { name: 'AWS' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Docker' })).toHaveCount(0)
  expect(problems).toEqual([])
})
