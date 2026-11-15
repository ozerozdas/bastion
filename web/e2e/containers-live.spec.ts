import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

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
  open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
}

/** finishedAsset is what the list returns after scan.finished invalidates it. */
const finishedAsset = {
  ...alpineAsset,
  last_scan: {
    scan_id: 12,
    status: 'succeeded',
    finished_at: '2026-11-14T11:00:00Z',
  },
  open_counts: { critical: 3, high: 0, medium: 0, low: 0, unknown: 0 },
}

/** fakeDockerApi serves one local image so the page renders a row. */
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

/**
 * fakeScanEvents serves /api/events as SSE frames. The first response is held
 * until release() so the test can assert the row before any event arrives; it
 * then carries the queued and progress frames. EventSource reconnects after
 * that response ends, and the next response carries scan.finished, which
 * invalidates the asset list.
 */
async function fakeScanEvents(
  page: Page,
  held: Promise<void>,
  onFinished: () => void,
) {
  let connections = 0
  await page.route('**/api/events', async (route) => {
    connections += 1
    if (connections === 1) {
      await held
      return route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        body: [
          'retry: 2000',
          '',
          'event: scan.queued',
          'data: {"type":"scan.queued","scan_id":12,"asset_id":7,"status":"queued"}',
          '',
          'event: scan.progress',
          'data: {"type":"scan.progress","scan_id":12,"asset_id":7,"status":"running","stage":"wait_db"}',
          '',
          '',
        ].join('\n'),
      })
    }
    onFinished()
    return route.fulfill({
      status: 200,
      contentType: 'text/event-stream',
      body: [
        'event: scan.finished',
        'data: {"type":"scan.finished","scan_id":12,"asset_id":7,"status":"succeeded"}',
        '',
        '',
      ].join('\n'),
    })
  })
}

test('Containers shows a scan progress and result without a reload', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeDockerApi(page)

  let finished = false
  let release = () => {}
  const held = new Promise<void>((resolve) => {
    release = resolve
  })
  await fakeScanEvents(page, held, () => {
    finished = true
  })
  await page.route('**/api/assets', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ assets: [finished ? finishedAsset : alpineAsset] }),
    }),
  )

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Containers, 1' }).click()

  const row = page.getByRole('row').filter({ hasText: 'alpine:3.20' })
  // The stream is still held, so the row shows the list's last scan.
  await expect(row.getByText('succeeded', { exact: true })).toBeVisible()

  // The queued/progress frames win over the row until the finished frame
  // refetches the list.
  release()
  await expect(row.getByText('running', { exact: true })).toBeVisible()
  await expect(row.getByText('Waiting for vulnerability DB')).toBeVisible()

  // scan.finished invalidates the asset query, so the same row shows the new
  // scan's findings without a reload.
  await expect(row.getByLabel('3 open critical findings')).toBeVisible()
  await expect(row.getByText('succeeded', { exact: true })).toBeVisible()

  expect(problems).toEqual([])
})
