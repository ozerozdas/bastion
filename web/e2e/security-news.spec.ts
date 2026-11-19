import type { Page } from '@playwright/test'

import { expect, openConfiguration, test, watch } from './fixtures'

// The feed is stubbed: e2e must never reach a real security site.
const sources = [
  { id: 'example', name: 'Example Feed', recommended: true, enabled: true },
]

const items = [
  {
    title: 'Critical advisory',
    source: 'Example Feed',
    source_id: 'example',
    published: '2026-11-15T12:00:00Z',
    link: 'https://example.com/advisory',
    summary: 'Patch now.',
  },
]

/** stubSecurityNews answers /api/security-news from in-page state. */
async function stubSecurityNews(page: Page, initial = false) {
  let enabled = initial
  await page.route('**/api/security-news', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = route.request().postDataJSON() as { enabled: boolean }
      enabled = body.enabled
    }
    await route.fulfill({
      json: { enabled, sources, items: enabled ? items : [] },
    })
  })
}

test('Security News is off by default and turns on from Configuration', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await stubSecurityNews(page)

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  // Off by default: no sidebar entry and no dashboard section.
  await expect(
    page.getByRole('link', { name: 'Security News', exact: true }),
  ).toHaveCount(0)
  await expect(
    page.getByRole('heading', { name: 'Security News', exact: true }),
  ).toHaveCount(0)

  // The Configuration card lists the preset sources with their toggles.
  await openConfiguration(page)
  const region = page.getByRole('region', { name: 'Security News' })
  await expect(region).toBeVisible()
  await expect(
    region.getByRole('switch', { name: 'Example Feed' }),
  ).toBeVisible()

  await region
    .getByRole('switch', { name: 'Security News', exact: true })
    .click()
  await expect(
    region.getByRole('switch', { name: 'Example Feed' }),
  ).toBeEnabled()

  // The sidebar entry appears once the feature is on.
  const navLink = page.getByRole('link', {
    name: 'Security News',
    exact: true,
  })
  await expect(navLink).toBeVisible()
  await navLink.click()
  await expect(
    page.getByRole('heading', { level: 1, name: 'Security News' }),
  ).toBeVisible()

  // Links open in a new tab and never leak the opener.
  const article = page.getByRole('link', { name: 'Critical advisory' })
  await expect(article).toHaveAttribute('target', '_blank')
  await expect(article).toHaveAttribute('rel', 'noopener noreferrer')

  // The dashboard shows the feed section at the bottom.
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click()
  const section = page.getByRole('region', { name: 'Security News' })
  await expect(section).toBeVisible()
  await expect(
    section.getByRole('link', { name: 'Critical advisory' }),
  ).toHaveAttribute('rel', 'noopener noreferrer')

  expect(problems).toEqual([])
})
