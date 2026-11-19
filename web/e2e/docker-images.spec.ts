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
  await expect(page.getByRole('heading', { name: 'Local daemon' })).toBeVisible()
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

  // The source tabs share the page's header band, with the title and stats.
  const band = page.locator('#page-band')
  await expect(
    band.getByRole('heading', { level: 1, name: 'Containers' }),
  ).toBeVisible()
  await expect(band.getByText('Local images', { exact: true })).toBeVisible()
  await expect(band.getByRole('tablist')).toBeVisible()

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
  // A scanned asset's name links to its findings page.
  await expect(row.getByRole('link', { name: 'alpine:3.20' })).toHaveAttribute(
    'href',
    '/findings/7',
  )
  // View findings sits in the row's ⋯ menu.
  await row.getByRole('button', { name: 'Actions for alpine:3.20' }).click()
  await expect(
    page.getByRole('menuitem', { name: 'View findings' }),
  ).toHaveAttribute('href', '/findings?asset=7')
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
  // Without a daemon the card stays, muted.
  await expect(page.getByText('not connected', { exact: true })).toBeVisible()
  expect(problems).toEqual([])
})

test('Containers removes a tracked image after confirming', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page, true)

  let assets: unknown[] = [alpineAsset]
  await page.route('**/api/assets/7', (route) => {
    assets = []
    return route.fulfill({ status: 204, body: '' })
  })
  await page.route('**/api/assets', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ assets }),
    }),
  )

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers, 1' }).click()

  const row = page.getByRole('row').filter({ hasText: 'alpine:3.20' })
  await row.getByRole('button', { name: 'Actions for alpine:3.20' }).click()
  await page.getByRole('menuitem', { name: 'Remove' }).click()

  const confirm = page
    .getByRole('row')
    .filter({ hasText: 'Its findings are hidden and it leaves this list' })
  await expect(confirm).toBeVisible()

  const removeRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets/7') && request.method() === 'DELETE',
  )
  await confirm.getByRole('button', { name: 'Remove' }).click()
  await removeRequest

  // The daemon still lists the image; the row is untracked again, so its menu
  // keeps only the link/schedule choices and Scan stays the primary action.
  const untracked = page.getByRole('row').filter({ hasText: 'alpine:3.20' })
  await expect(
    untracked.getByRole('button', { name: 'Actions for alpine:3.20' }),
  ).toBeVisible()
  await expect(untracked.getByRole('button', { name: 'Scan' })).toBeVisible()
  expect(problems).toEqual([])
})

test('an untracked image is tracked by linking or scheduling it', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page, true)

  const repo = {
    id: 1,
    kind: 'repo',
    display_name: 'acme/api',
    ref: 'acme/api',
    default_branch: 'main',
    created_at: '2026-11-01T10:00:00Z',
    scan_schedule: 'off',
    open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    linked_images: [],
  }
  const created = {
    id: 9,
    kind: 'image',
    display_name: 'nginx:latest',
    ref: 'nginx:latest',
    created_at: '2026-11-16T10:00:00Z',
    scan_schedule: 'off',
    open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    linked_images: [],
  }
  let assets: unknown[] = [repo]
  const posted: unknown[] = []
  await page.route('**/api/assets', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({ json: { assets } })
    }
    posted.push(route.request().postDataJSON())
    assets = [...assets, created]
    return route.fulfill({ status: 201, json: created })
  })
  let linked: unknown = null
  await page.route('**/api/assets/9/link', (route) => {
    linked = route.request().postDataJSON()
    const asset = {
      ...created,
      linked_repo: {
        asset_id: 1,
        ref: 'acme/api',
        display_name: 'acme/api',
        source: 'manual',
      },
    }
    assets = [repo, asset]
    return route.fulfill({ json: asset })
  })
  let scheduled: unknown = null
  await page.route('**/api/assets/9/schedule', (route) => {
    scheduled = route.request().postDataJSON()
    return route.fulfill({ json: { ...created, scan_schedule: 'daily' } })
  })

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers' }).click()

  const row = page.getByRole('row').filter({ hasText: 'nginx:latest' })
  await row.getByRole('button', { name: 'Actions for nginx:latest' }).click()

  // Nothing to view, unlink or remove yet; the choices are the tracking paths.
  await expect(page.getByRole('menuitem', { name: 'View findings' })).toHaveCount(0)
  await expect(page.getByRole('menuitem', { name: 'Remove' })).toHaveCount(0)
  await page.getByRole('menuitem', { name: 'Link to repository…' }).click()

  const dialog = page.getByRole('dialog', {
    name: 'Link nginx:latest to a repository',
  })
  await dialog.getByRole('radio', { name: /acme\/api/ }).check()
  await dialog.getByRole('button', { name: 'Link', exact: true }).click()

  await expect.poll(() => posted.length).toBe(1)
  expect(posted[0]).toEqual({ kind: 'image', ref: 'nginx:latest' })
  await expect.poll(() => linked).toEqual({ repo_asset_id: 1 })
  await expect(row.getByText('acme/api', { exact: true })).toBeVisible()

  // The image is tracked now, so the schedule goes straight to the asset.
  await row.getByRole('button', { name: 'Actions for nginx:latest' }).click()
  await page
    .getByRole('group', { name: 'Scan schedule for nginx:latest' })
    .getByRole('menuitemradio', { name: 'Daily' })
    .click()
  await expect.poll(() => scheduled).toEqual({ schedule: 'daily' })
  expect(problems).toEqual([])
})
