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

test('asks for the release check once and remembers "no thanks"', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server.url)

  await expect(page.getByText(consentQuestion, { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'No thanks' }).click()
  await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

  await page.reload()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

  expect(problems).toEqual([])
})

test('remembers an accepted release check after reload', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server.url)

  await expect(page.getByText(consentQuestion, { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Turn on' }).click()
  await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

  await page.reload()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await expect(page.getByText(consentQuestion, { exact: true })).toHaveCount(0)

  expect(problems).toEqual([])
})

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
