import type { Page } from '@playwright/test'

import { expect, test, watch, type Server } from './fixtures'

const imageRef = 'acme/api:1.2.3'

/**
 * openSession exchanges the startup token and waits for the dashboard, so a
 * click never races the exchange page's meta-refresh navigation.
 */
async function openSession(page: Page, server: Server) {
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
}


const repoAsset = {
  id: 1,
  kind: 'repo',
  display_name: 'acme/api',
  ref: 'acme/api',
  default_branch: 'main',
  created_at: '2026-11-14T10:00:00Z',
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  linked_images: [
    {
      asset_id: 2,
      ref: imageRef,
      display_name: imageRef,
      source: 'oci',
      revision: '9f2c1ab',
    },
  ],
}

const imageAsset = {
  id: 2,
  kind: 'image',
  display_name: imageRef,
  ref: imageRef,
  created_at: '2026-11-14T10:00:00Z',
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  linked_images: [],
  linked_repo: {
    asset_id: 1,
    ref: 'acme/api',
    display_name: 'acme/api',
    source: 'oci',
    revision: '9f2c1ab',
  },
}

/** fakeDockerApi serves one tracked image from the daemon probe. */
async function fakeDockerApi(page: Page) {
  await page.route('**/api/docker/images', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        available: true,
        host: 'unix:///var/run/docker.sock',
        images: [
          {
            reference: imageRef,
            id: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            size_bytes: 12 * 1024 * 1024,
            created_at: '2026-11-01T10:00:00Z',
          },
        ],
      }),
    }),
  )
}

/**
 * fakeAssetsApi serves the asset list from a mutable link state and records the
 * link requests, so a test can assert what the UI asked the API to do.
 */
async function fakeAssetsApi(page: Page, linked: { value: boolean }) {
  await page.route('**/api/assets/*/link', async (route) => {
    const method = route.request().method()
    if (method === 'DELETE') {
      linked.value = false
      return route.fulfill({ status: 204 })
    }
    linked.value = true
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(imageAsset),
    })
  })
  await page.route('**/api/assets', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        assets: [
          repoAsset,
          linked.value
            ? imageAsset
            : { ...imageAsset, linked_repo: undefined },
        ],
      }),
    }),
  )
}

test('Containers shows the linked repository and unlinks it', async ({ page, server }) => {
  const problems = watch(page)
  const linked = { value: true }
  await fakeDockerApi(page)
  await fakeAssetsApi(page, linked)

  await openSession(page, server)
  await page.getByRole('link', { name: 'Containers' }).click()

  const row = page.getByRole('row').filter({ hasText: imageRef })
  await expect(row.getByText('acme/api', { exact: true })).toBeVisible()
  await expect(row.getByText('oci', { exact: true })).toBeVisible()

  await row.getByRole('button', { name: `Actions for ${imageRef}` }).click()
  const unlinkRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets/2/link') &&
      request.method() === 'DELETE',
  )
  await page.getByRole('menuitem', { name: 'Unlink' }).click()
  await unlinkRequest

  // Unlinked, the row shows a dash and the menu offers the picker again.
  await row.getByRole('button', { name: `Actions for ${imageRef}` }).click()
  await expect(
    page.getByRole('menuitem', { name: 'Link to repository…' }),
  ).toBeVisible()
  expect(problems).toEqual([])
})

test('Containers links an image to a repository by hand', async ({ page, server }) => {
  const problems = watch(page)
  const linked = { value: false }
  await fakeDockerApi(page)
  await fakeAssetsApi(page, linked)

  await openSession(page, server)
  await page.getByRole('link', { name: 'Containers' }).click()

  const row = page.getByRole('row').filter({ hasText: imageRef })
  await row.getByRole('button', { name: `Actions for ${imageRef}` }).click()
  const linkRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets/2/link') && request.method() === 'PUT',
  )
  await page.getByRole('menuitem', { name: 'Link to repository…' }).click()

  const dialog = page.getByRole('dialog', {
    name: `Link ${imageRef} to a repository`,
  })
  await dialog.getByRole('searchbox').fill('acme')
  await dialog.getByRole('radio', { name: /acme\/api/ }).check()
  await dialog.getByRole('button', { name: 'Link', exact: true }).click()

  expect((await linkRequest).postDataJSON()).toEqual({ repo_asset_id: 1 })
  await expect(row.getByText('acme/api', { exact: true })).toBeVisible()
  expect(problems).toEqual([])
})

test('Repositories shows the images linked to a repository', async ({ page, server }) => {
  const problems = watch(page)
  const linked = { value: true }
  await fakeAssetsApi(page, linked)

  await openSession(page, server)
  await page.getByRole('link', { name: 'Repositories' }).click()

  const row = page.getByRole('row').filter({ hasText: 'acme/api' })
  // The images cell is a count; the names are one hover away.
  await row
    .getByRole('button', { name: 'Images linked to acme/api' })
    .hover()
  await expect(page.getByRole('tooltip')).toContainText(imageRef)
  expect(problems).toEqual([])
})
