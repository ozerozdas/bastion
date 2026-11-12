import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

const consentQuestion = 'Check for new releases?'

/** openSession exchanges the startup token and waits for the shell. */
async function openSession(page: Page, url: string) {
  await page.goto(url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
}

/**
 * fakeUpdateApi answers /api/update from in-page state. The e2e server runs
 * with BASTION_NO_UPDATE_CHECK=1 (it must never call github.com), so it reports
 * the check as disabled; the consent flow is driven through this stub, and
 * server-side persistence is covered by the Go handler tests.
 */
async function fakeUpdateApi(page: Page) {
  let consent: 'unset' | 'on' | 'off' = 'unset'
  const body = () =>
    JSON.stringify({
      current: 'v0.1.1',
      update_available: false,
      consent,
      disabled: false,
    })
  await page.route('**/api/update/consent', async (route) => {
    const { enabled } = route.request().postDataJSON() as { enabled: boolean }
    consent = enabled ? 'on' : 'off'
    await route.fulfill({ status: 200, contentType: 'application/json', body: body() })
  })
  await page.route('**/api/update', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: body() }),
  )
}

test('does not ask when the release check is disabled', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  // Wait for the real answer before asserting that nothing is rendered.
  const answered = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/api/update',
  )
  await openSession(page, server.url)
  const status = (await (await answered).json()) as { disabled: boolean }
  expect(status.disabled).toBe(true)
  await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

  expect(problems).toEqual([])
})

for (const [answer, label] of [
  ['no thanks', 'No thanks'],
  ['an accepted check', 'Turn on'],
] as const) {
  test(`asks for the release check once and remembers ${answer}`, async ({
    page,
    server,
  }) => {
    const problems = watch(page)
    await fakeUpdateApi(page)
    await openSession(page, server.url)

    await expect(page.getByText(consentQuestion, { exact: true })).toBeVisible()
    await page.getByRole('button', { name: label }).click()
    await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

    await page.reload()
    await expect(
      page.getByRole('heading', { level: 1, name: 'Dashboard' }),
    ).toBeVisible()
    await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

    expect(problems).toEqual([])
  })
}

test('shows the update command, release notes and a per-version dismiss', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  const release = {
    current: 'v0.1.0',
    latest: 'v0.1.2',
    update_available: true,
    consent: 'on',
    disabled: false,
    command: 'brew upgrade ozerozdas/tap/bastion',
    release_url: 'https://github.com/ozerozdas/bastion/releases/tag/v0.1.2',
  }
  // The server never calls github.com in tests, so the answer the UI renders
  // comes from this route.
  await page.route('**/api/update', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(release),
    }),
  )

  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await openSession(page, server.url)

  await expect(page.getByText('v0.1.2 is available', { exact: true })).toBeVisible()
  await expect(
    page.getByText(release.command, { exact: true }),
  ).toBeVisible()

  const notes = page.getByRole('link', { name: 'Release notes' })
  await expect(notes).toHaveAttribute('href', release.release_url)
  await expect(notes).toHaveAttribute('target', '_blank')
  await expect(notes).toHaveAttribute('rel', /noopener/)

  await page.getByRole('button', { name: 'Copy update command' }).click()
  await expect(page.getByText('Copied', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Dismiss update notice' }).click()
  await expect(page.getByText('v0.1.2 is available', { exact: true })).toHaveCount(0)

  // The dismissal is per version and survives a reload.
  await page.reload()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await expect(page.getByText('v0.1.2 is available', { exact: true })).toHaveCount(0)

  expect(problems).toEqual([])
})
