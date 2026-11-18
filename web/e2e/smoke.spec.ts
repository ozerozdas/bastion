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
    marker: 'No repositories yet',
  },
  {
    label: 'Repositories',
    path: '/repositories',
    subtitle: 'GitHub repositories and local paths you scan',
    marker: 'Add a local path',
  },
  {
    label: 'Containers',
    path: '/containers',
    subtitle: 'Images on the local Docker daemon',
    // The AWS hint renders whether or not this machine has a daemon, so the
    // marker does not depend on the environment the suite runs in.
    marker: 'No AWS connection yet.',
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

test('renders every nav page without browser errors', async ({
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
  expect(labels).toEqual([
    'Dashboard',
    'Findings',
    'Repositories',
    'Containers',
    'Connections',
  ])

  // Scan History is a tab now, not a sidebar entry.
  await expect(aside.getByRole('link', { name: /Scan History/ })).toHaveCount(0)

  // Configuration is the SETTINGS action, next to Connections (#142); the old
  // standalone button above the Local · version footer is gone.
  await expect(
    aside
      .getByRole('group', { name: 'SETTINGS' })
      .getByRole('button', { name: 'Configuration' }),
  ).toBeVisible()
  await expect(
    aside.getByRole('button', { name: 'Settings', exact: true }),
  ).toHaveCount(0)

  expect(problems).toEqual([])
})

test('Repositories tabs live in the URL and move with arrow keys', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await openSession(page, server)
  await page.getByRole('link', { name: 'Repositories', exact: true }).click()

  const projectsTab = page.getByRole('tab', { name: 'Repositories', exact: true })
  const scansTab = page.getByRole('tab', { name: 'Scans', exact: true })
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')
  await expect(projectsTab).toHaveAttribute('tabindex', '0')
  await expect(scansTab).toHaveAttribute('aria-selected', 'false')
  await expect(scansTab).toHaveAttribute('tabindex', '-1')
  await expect(
    page.getByRole('heading', { level: 1, name: 'Repositories' }),
  ).toBeVisible()

  const origin = new URL(page.url()).origin

  // Clicking the tab changes only the URL; the tablist is not local state.
  await scansTab.click()
  await expect(page).toHaveURL(`${origin}/repositories?tab=scans`)
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByText('No scans yet — add a repository and press Scan', {
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
  await expect(page).toHaveURL(`${origin}/repositories?tab=scans`)

  // Automatic activation: ArrowLeft/ArrowRight wrap, Home/End jump.
  await scansTab.focus()
  await page.keyboard.press('ArrowLeft')
  await expect(projectsTab).toBeFocused()
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/repositories`)

  await page.keyboard.press('ArrowRight')
  await expect(scansTab).toBeFocused()
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/repositories?tab=scans`)

  await page.keyboard.press('Home')
  await expect(projectsTab).toBeFocused()
  await expect(projectsTab).toHaveAttribute('aria-selected', 'true')

  await page.keyboard.press('End')
  await expect(scansTab).toBeFocused()
  await expect(scansTab).toHaveAttribute('aria-selected', 'true')

  expect(problems).toEqual([])
})

test('Connections tabs live in the URL', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  await page.getByRole('link', { name: 'Connections', exact: true }).click()

  const repositoryTab = page.getByRole('tab', {
    name: 'Repository',
    exact: true,
  })
  const registryTab = page.getByRole('tab', { name: 'Registry', exact: true })
  await expect(repositoryTab).toHaveAttribute('aria-selected', 'true')
  await expect(
    page.getByRole('heading', { name: 'Add GitHub connection' }),
  ).toBeVisible()

  // Registry is the bare path's alternative, so it is in the URL (#107).
  await registryTab.click()
  const origin = new URL(page.url()).origin
  await expect(page).toHaveURL(`${origin}/connections?tab=registry`)
  await expect(
    page.getByRole('heading', { name: 'AWS' }),
  ).toBeVisible()
  await expect(
    page.getByRole('heading', { name: 'Add GitHub connection' }),
  ).toHaveCount(0)

  await page.reload()
  await expect(
    page.getByRole('tab', { name: 'Registry', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')
  await expect(page).toHaveURL(`${origin}/connections?tab=registry`)

  await page.getByRole('tab', { name: 'Repository', exact: true }).click()
  await expect(page).toHaveURL(`${origin}/connections`)

  expect(problems).toEqual([])
})

test('redirects /projects to /repositories', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/projects`)
  await expect(page).toHaveURL(`${origin}/repositories`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Repositories' }),
  ).toBeVisible()

  // The query string survives, so an old Scans-tab link still opens it.
  await page.goto(`${origin}/projects?tab=scans`)
  await expect(page).toHaveURL(`${origin}/repositories?tab=scans`)
  await expect(
    page.getByRole('tab', { name: 'Scans', exact: true }),
  ).toHaveAttribute('aria-selected', 'true')

  expect(problems).toEqual([])
})

test('redirects /scan-history to the Scans tab', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  const origin = new URL(page.url()).origin

  await page.goto(`${origin}/scan-history`)
  await expect(page).toHaveURL(`${origin}/repositories?tab=scans`)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Repositories' }),
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
  await page.getByRole('link', { name: 'Repositories', exact: true }).click()
  await page.getByRole('button', { name: 'Add repository' }).click()
  await page.getByLabel('Or add a local path').fill(server.projectDir)
  await page.getByRole('button', { name: 'Add path' }).click()

  const name = basename(server.projectDir)
  const row = page.getByRole('row', { name: new RegExp(name) })
  // View findings moved into the row's ⋯ menu; the item is still a link.
  await row.getByRole('button', { name: `Actions for ${name}` }).click()
  const findingsLink = page.getByRole('menuitem', { name: 'View findings' })
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

test('adds a local path repository through the UI', async ({ page, server }) => {
  const problems = watch(page)
  await openSession(page, server)
  await page.getByRole('link', { name: 'Repositories', exact: true }).click()

  const name = basename(server.projectDir)
  await page.getByRole('button', { name: 'Add repository' }).click()
  await page.getByLabel('Or add a local path').fill(server.projectDir)
  await page.getByRole('button', { name: 'Add path' }).click()

  // Success closes the modal; the new row is what proves the add worked.
  await expect(page.getByRole('dialog')).toHaveCount(0)

  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toBeVisible()
  // The row shows the directory's base name and keeps the absolute path in Ref.
  await expect(row.getByText(server.projectDir, { exact: true })).toBeVisible()
  // The old Kind column is gone; the table starts with Repository.
  await expect(page.getByRole('columnheader', { name: 'Kind' })).toHaveCount(0)

  expect(problems).toEqual([])
})
