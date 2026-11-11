import { basename } from 'node:path'

import type { Page } from '@playwright/test'

import { expect, test, watch, type Server } from './fixtures'

/**
 * navPages mirrors web/src/lib/nav.tsx: the five sections of §7, the heading the
 * header shows and the subtitle under it.
 */
const navPages = [
  {
    label: 'Dashboard',
    path: '/',
    subtitle: 'Open findings across your projects',
    marker: 'No scans yet',
  },
  {
    label: 'Connections',
    path: '/connections',
    subtitle: 'GitHub, AWS and Docker sources',
    marker: 'Add GitHub connection',
  },
  {
    label: 'Projects',
    path: '/projects',
    subtitle: 'Repositories and images you scan',
    marker: 'Add projects',
  },
  {
    label: 'Security Reports',
    path: '/security-reports',
    subtitle: 'Findings per project, with fixes',
    marker: 'No projects yet',
  },
  {
    label: 'Scan History',
    path: '/scan-history',
    subtitle: 'Every scan, comparable side by side',
    marker: 'No scans yet — add a project and press Scan',
  },
]

/** openSession exchanges the startup token and lands on the dashboard. */
async function openSession(page: Page, server: Server) {
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  // The single-use token leaves the address bar immediately.
  expect(new URL(page.url()).search).toBe('')
}

test('exchanges the startup token for a session cookie', async ({
  page,
  server,
}) => {
  const problems = watch(page)

  await openSession(page, server)

  const cookies = await page.context().cookies()
  expect(cookies).toContainEqual(
    expect.objectContaining({ name: 'bastion_session', httpOnly: true }),
  )
  expect(problems).toEqual([])
})

test('renders all five nav pages without browser errors', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server)

  for (const item of navPages) {
    await page.getByRole('link', { name: item.label, exact: true }).click()

    await expect(
      page.getByRole('heading', { level: 1, name: item.label }),
    ).toBeVisible()
    await expect(
      page.locator('header').getByText(item.subtitle, { exact: true }),
    ).toBeVisible()
    // The marker only renders once the page's first API call succeeded.
    await expect(
      page.getByText(item.marker, { exact: true }).first(),
    ).toBeVisible()
    expect(new URL(page.url()).pathname).toBe(item.path)
  }

  expect(problems).toEqual([])
})

test('adds a local path project through the UI', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  await page.getByRole('link', { name: 'Projects', exact: true }).click()

  const name = basename(server.projectDir)
  await page.getByLabel('Or add a local path').fill(server.projectDir)
  await page.getByRole('button', { name: 'Add path' }).click()

  await expect(
    page.getByText(
      'Local path added. Press Scan on its row to run the first scan.',
    ),
  ).toBeVisible()

  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toBeVisible()
  // The row shows the directory's base name and keeps the absolute path in Ref.
  await expect(row.getByText(server.projectDir, { exact: true })).toBeVisible()
  await expect(row.getByText('path', { exact: true })).toBeVisible()

  expect(problems).toEqual([])
})
