import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

const registry = '143709573002.dkr.ecr.eu-central-1.amazonaws.com'
const digest =
  'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
const ref = `${registry}/t2n-api@${digest}`

const awsConnection = {
  id: 1,
  kind: 'aws',
  name: 'prod',
  status: 'ok',
  created_at: '2026-11-01T10:00:00Z',
  region: 'eu-central-1',
  account: '143709573002',
}

const ecrDiscovery = {
  repos: [],
  ecr_repositories: [
    {
      name: 't2n-api',
      uri: `${registry}/t2n-api`,
      tags: [
        {
          tags: ['v1.2.3'],
          digest,
          ref,
          pushed_at: '2026-11-10T10:00:00Z',
          already_added: false,
        },
      ],
    },
  ],
}

/** fakeConnectionsApi serves the connection list the ECR section reads. */
async function fakeConnectionsApi(page: Page, connections: unknown[]) {
  await page.route('**/api/connections', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ connections }),
    }),
  )
}

/** fakeEcrDiscovery serves one AWS connection's repositories and tags. */
async function fakeEcrDiscovery(page: Page) {
  await page.route('**/api/connections/1/discover', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(ecrDiscovery),
    }),
  )
}

/** fakeNoDocker keeps the local section out of the way. */
async function fakeNoDocker(page: Page) {
  await page.route('**/api/docker/images', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ available: false, host: '', images: [] }),
    }),
  )
}

/** fakeDocker serves one local image, so the Docker tab exists. */
async function fakeDocker(page: Page) {
  await page.route('**/api/docker/images', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        available: true,
        host: 'unix:///var/run/docker.sock',
        images: [
          {
            reference: 'alpine:3.20',
            id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            size_bytes: 8 * 1024 * 1024,
            created_at: '2026-11-01T10:00:00Z',
          },
        ],
      }),
    }),
  )
}

const createdAsset = {
  id: 9,
  kind: 'image',
  display_name: 't2n-api:v1.2.3',
  ref,
  connection_id: 1,
  created_at: '2026-11-14T10:00:00Z',
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
}

test('Containers adds and scans an ECR tag by its digest', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeNoDocker(page)
  await fakeConnectionsApi(page, [awsConnection])
  await fakeEcrDiscovery(page)

  await page.route('**/api/assets', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ assets: [] }),
      })
    }
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify(createdAsset),
    })
  })
  await page.route('**/api/scans', (route) =>
    route.fulfill({
      status: 202,
      contentType: 'application/json',
      body: JSON.stringify({ scans: [{ scan_id: 12, asset_id: 9 }] }),
    }),
  )

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers', exact: true }).click()

  await expect(
    page.getByRole('tab', { name: 'AWS (prod)', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  const row = page.getByRole('row').filter({ hasText: 't2n-api:v1.2.3' })
  await expect(row).toBeVisible()

  const assetRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets') && request.method() === 'POST',
  )
  const scanRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/scans') && request.method() === 'POST',
  )

  await row.getByRole('button', { name: 'Add & scan' }).click()

  expect((await assetRequest).postDataJSON()).toEqual({
    kind: 'image',
    ref,
    tag: 'v1.2.3',
    connection_id: 1,
  })
  expect((await scanRequest).postDataJSON()).toEqual({ asset_ids: [9] })
  expect(problems).toEqual([])
})

test('Containers hints at Connections when no AWS connection exists', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeNoDocker(page)
  await fakeConnectionsApi(page, [])

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers', exact: true }).click()

  await expect(page.getByText('No AWS connection yet.', { exact: false })).toBeVisible()
  await expect(
    page.getByRole('link', { name: 'Connections → Registry' }),
  ).toHaveAttribute('href', '/connections?tab=registry')
  expect(problems).toEqual([])
})

test('Containers groups orphaned ECR images and archives one', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeNoDocker(page)
  await fakeConnectionsApi(page, [])

  const orphaned = {
    id: 21,
    kind: 'image',
    display_name: 't2n-api:v1.2.3',
    ref,
    ecr_registry: registry,
    created_at: '2026-11-14T10:00:00Z',
    open_counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
    linked_images: [],
  }
  let assets = [orphaned]
  await page.route('**/api/assets/21', (route) => {
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
  // The sidebar badge adds the asset count to the link's accessible name.
  await page.getByRole('link', { name: /^Containers/ }).click()

  await expect(
    page.getByRole('tab', { name: 'Orphaned', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  const row = page.getByRole('row').filter({ hasText: 't2n-api:v1.2.3' })
  await expect(row).toBeVisible()

  const archiveRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/assets/21') && request.method() === 'DELETE',
  )
  await row.getByRole('button', { name: 'Archive' }).click()
  await archiveRequest

  // The last orphan leaves, so its tab goes with it.
  await expect(
    page.getByRole('tab', { name: 'Orphaned', exact: true }),
  ).toHaveCount(0)
  expect(problems).toEqual([])
})

test('Containers tabs switch sources and live in the URL', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDocker(page)
  await fakeConnectionsApi(page, [awsConnection])
  await fakeEcrDiscovery(page)
  await page.route('**/api/assets', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ assets: [] }),
    }),
  )

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers', exact: true }).click()

  const origin = new URL(page.url()).origin
  const dockerTab = page.getByRole('tab', { name: 'Docker', exact: true })
  const awsTab = page.getByRole('tab', { name: 'AWS (prod)', exact: true })

  // The first available source is the bare path and the default tab.
  await expect(dockerTab).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/containers`)
  await expect(page.getByText('alpine:3.20', { exact: true })).toBeVisible()

  // One tab per AWS connection, named after it, with its id in the URL.
  await awsTab.click()
  await expect(page).toHaveURL(`${origin}/containers?tab=aws-1`)
  await expect(awsTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByRole('row').filter({ hasText: 't2n-api:v1.2.3' }),
  ).toBeVisible()
  await expect(page.getByText('alpine:3.20', { exact: true })).toHaveCount(0)

  // Reload keeps the tab, because it is in the URL.
  await page.reload()
  await expect(
    page.getByRole('tab', { name: 'AWS (prod)', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')

  // A stale tab (that connection is gone) falls back to the first one.
  await page.goto(`${origin}/containers?tab=aws-9`)
  await expect(
    page.getByRole('tab', { name: 'Docker', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  expect(problems).toEqual([])
})
