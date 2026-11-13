import { basename } from 'node:path'

import type { Page } from '@playwright/test'

import { expect, test, watch, type Server } from './fixtures'

/**
 * navPages mirrors web/src/lib/nav.tsx: the ADR-007 sections in order, the
 * heading the header shows and the subtitle under it.
 */
const navPages = [
  {
    label: 'Dashboard',
    path: '/',
    subtitle: 'Open findings across your projects',
    marker: 'No scans yet',
  },
  {
    label: 'Findings',
    path: '/findings',
    subtitle: 'Across every project, with fixes',
    marker: 'No projects yet',
  },
  {
    label: 'Projects',
    path: '/projects',
    subtitle: 'Repositories and images you scan',
    marker: 'Add projects',
  },
  {
    label: 'Connections',
    path: '/connections',
    subtitle: 'GitHub, AWS and Docker sources',
    marker: 'Add GitHub connection',
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

test('renders all four nav pages without browser errors', async ({
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

test('groups the sidebar into ASSETS and SETTINGS', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)

  const aside = page.locator('aside')
  await expect(
    aside.getByRole('heading', { name: 'ASSETS', exact: true }),
  ).toBeVisible()
  await expect(
    aside.getByRole('heading', { name: 'SETTINGS', exact: true }),
  ).toBeVisible()

  // Order is the ADR-007 one: Findings moved up, Connections moved down.
  const labels = await aside
    .getByRole('link')
    .evaluateAll((links) =>
      links.map((link) => link.getAttribute('aria-label')),
    )
  expect(labels).toEqual(['Dashboard', 'Findings', 'Projects', 'Connections'])

  // Scan History is a tab now, not a sidebar entry.
  await expect(aside.getByRole('link', { name: /Scan History/ })).toHaveCount(0)

  expect(problems).toEqual([])
})

test('Projects tabs live in the URL and move with arrow keys', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server)
  await page.getByRole('link', { name: 'Projects', exact: true }).click()

  const projectsTab = page.getByRole('tab', { name: 'Projects', exact: true })
  const scansTab = page.getByRole('tab', { name: 'Scans', exact: true })
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')
  await expect(projectsTab).toHaveAttribute('tabindex', '0')
  await expect(scansTab).toHaveAttribute('aria-selected', 'false')
  await expect(scansTab).toHaveAttribute('tabindex', '-1')
  await expect(
    page.getByRole('heading', { level: 1, name: 'Projects' }),
  ).toBeVisible()

  const origin = new URL(page.url()).origin

  // Clicking the tab changes only the URL; the tablist is not local state.
  await scansTab.click()
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByText('No scans yet — add a project and press Scan', {
      exact: true,
    }),
  ).toBeVisible()

  // The panel is labelled by the selected tab, and vice versa.
  const scansId = await scansTab.getAttribute('id')
  await expect(page.getByRole('tabpanel')).toHaveAttribute(
    'aria-labelledby',
    scansId ?? '',
  )

  // Reload keeps the tab, because it is in the URL.
  await page.reload()
  await expect(
    page.getByRole('tab', { name: 'Scans', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)

  // Automatic activation: ArrowLeft/ArrowRight wrap, Home/End jump.
  await scansTab.focus()
  await page.keyboard.press('ArrowLeft')
  await expect(projectsTab).toBeFocused()
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/projects`)

  await page.keyboard.press('ArrowRight')
  await expect(scansTab).toBeFocused()
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)

  await page.keyboard.press('Home')
  await expect(projectsTab).toBeFocused()
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')

  await page.keyboard.press('End')
  await expect(scansTab).toBeFocused()
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')

  expect(problems).toEqual([])
})

test('redirects /scan-history to the Scans tab', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/scan-history`)
  await expect(page).toHaveURL(`${origin}/projects?tab=scans`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Projects' }),
  ).toBeVisible()
  await expect(
    page.getByRole('tab', { name: 'Scans', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')

  expect(problems).toEqual([])
})

test('drops a stale project id from the findings URL', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server)

  // One project: the page has something to fall back to when the id is gone.
  await page.getByRole('link', { name: 'Projects', exact: true }).click()
  await page.getByLabel('Or add a local path').fill(server.projectDir)
  await page.getByRole('button', { name: 'Add path' }).click()

  const name = basename(server.projectDir)
  const findingsLink = page
    .getByRole('row', { name: new RegExp(name) })
    .getByRole('link', { name: 'View findings' })
  await expect(findingsLink).toBeVisible()

  const origin = new URL(page.url()).origin
  const href = await findingsLink.getAttribute('href')
  const assetId = new URL(href ?? '', origin).searchParams.get('asset')
  if (assetId === null) {
    throw new Error(`View findings link has no ?asset= id: ${href ?? ''}`)
  }

  // The row's link opens the fleet-wide list filtered to that project.
  await page.goto(`${origin}/findings?asset=${assetId}`)
  await expect(page.locator('#findings-project')).toHaveValue(assetId)

  // A removed project id must not stay in the address bar. With no id meaning
  // every project, an unknown id is dropped and the list shows them all.
  await page.goto(`${origin}/findings?asset=999`)
  await expect(page).toHaveURL(`${origin}/findings`)
  await expect(page.locator('#findings-project')).toHaveValue('')

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
