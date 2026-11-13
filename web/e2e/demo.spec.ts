import { readFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'

import { expect, test } from '@playwright/test'

import { startServer, stopServer } from './fixtures'

// The first-report run: the Phase 1 exit check (timed) and the README demo
// (recorded). It needs network, a GitHub token and minutes for the Trivy DB, so
// it is skipped unless asked for:
//
//   BASTION_DEMO_TOKEN_FILE=~/.bastion-demo-token \
//   BASTION_DEMO_ROOT=/tmp/bastion-demo npx --prefix web playwright test demo
//
// BASTION_DEMO_ROOT keeps data/ and cache/; an empty root is a cold first run.
const tokenFile = process.env.BASTION_DEMO_TOKEN_FILE
const root = process.env.BASTION_DEMO_ROOT
const repo = process.env.BASTION_DEMO_REPO ?? 'snyk-labs/nodejs-goof'

test.skip(!tokenFile || !root, 'set BASTION_DEMO_TOKEN_FILE and BASTION_DEMO_ROOT')
test.use({
  viewport: { width: 1280, height: 800 },
  video: { mode: 'on', size: { width: 1280, height: 800 } },
})

test('first report: connect GitHub, add a repo, scan, read the report', async ({
  page,
}) => {
  test.setTimeout(20 * 60_000)
  const token = (await readFile(tokenFile!, 'utf8')).trim()
  const dataDir = join(root!, 'data')
  const cacheDir = join(root!, 'cache')
  await mkdir(dataDir, { recursive: true })
  await mkdir(cacheDir, { recursive: true })

  const started = Date.now()
  const mark = (step: string) =>
    console.log(`[demo] ${((Date.now() - started) / 1000).toFixed(1)}s ${step}`)
  const pause = () => page.waitForTimeout(900) // ponytail: readable GIF pacing

  const { child, url } = await startServer(dataDir, cacheDir)
  try {
    await page.goto(url)
    await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible()
    mark('ui open')
    await pause()

    await page.getByRole('link', { name: 'Connections' }).click()
    await page.locator('#github-name').fill('github')
    await page.locator('#github-token').fill(token)
    await pause()
    await page.getByRole('button', { name: 'Add connection' }).click()
    await expect(page.getByRole('button', { name: 'Test' })).toBeVisible()
    mark('github connected')
    await pause()

    await page.getByRole('link', { name: 'Projects' }).click()
    await page.getByRole('button', { name: 'Add project' }).click()
    await page.locator('#discover-search').pressSequentially(repo, { delay: 40 })
    await page.getByRole('button', { name: `Add ${repo}` }).click()
    const row = page.getByRole('row').filter({ hasText: repo.split('/')[1] })
    await expect(row).toBeVisible()
    mark('repo added')
    await pause()

    await row.getByRole('button', { name: 'Scan' }).click()
    await expect(row.getByText('succeeded')).toBeVisible({ timeout: 15 * 60_000 })
    mark('scan succeeded')
    await pause()

    await row.getByRole('link', { name: 'View findings' }).click()
    const firstFinding = page.locator('tbody tr').first()
    await expect(firstFinding).toBeVisible()
    mark('first report')
    await pause()

    await firstFinding.click()
    await page.locator('#finding-reason').pressSequentially('dev-only dependency', {
      delay: 30,
    })
    await page.getByRole('button', { name: 'Save decision' }).click()
    await page.keyboard.press('Escape')
    await pause()

    await page.getByRole('link', { name: 'Dashboard' }).click()
    await expect(page.getByText('Riskiest projects')).toBeVisible()
    await page.waitForTimeout(2500)
  } finally {
    // Removing the connection deletes its token from the OS keyring.
    const api = (path: string) => new URL(path, url).href
    const list = await page.request.get(api('/api/connections')).catch(() => null)
    for (const c of ((await list?.json().catch(() => null))?.connections ?? []) as {
      id: number
    }[]) {
      await page.request.delete(api(`/api/connections/${String(c.id)}`), {
        headers: { 'X-Bastion': '1' },
      })
    }
    await stopServer(child)
  }
})
