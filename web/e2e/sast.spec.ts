import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

type SASTStatus = {
  enabled: boolean
  state: 'not_installed' | 'installed' | 'checksum_bad'
  version: string
  installing: boolean
  error?: string
  install_error?: string
}

/**
 * stubSAST answers /api/sast from in-page state. The e2e server must never
 * download Opengrep, so the module state is entirely fake and the PUT records
 * what the card asked for.
 */
async function stubSAST(page: Page, initial: SASTStatus) {
  let state = initial
  const puts: boolean[] = []
  await page.route('**/api/sast', async (route) => {
    if (route.request().method() === 'PUT') {
      const { enabled } = route.request().postDataJSON() as { enabled: boolean }
      puts.push(enabled)
      state = enabled
        ? { enabled: true, state: 'installed', version: 'v1.33.1', installing: false }
        : { ...state, enabled: false }
    }
    await route.fulfill({ json: state })
  })
  return { puts }
}

test('SAST is off by default and explains the download', async ({ page, server }) => {
  const problems = watch(page)
  await stubSAST(page, {
    enabled: false,
    state: 'not_installed',
    version: 'v1.33.1',
    installing: false,
  })
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  const card = page.getByRole('region', { name: 'SAST' })
  await expect(card).toBeVisible()
  await expect(card).toContainText('Off')
  await expect(card).toContainText('~47 MB')
  await expect(card).toContainText('~1 MB')
  await expect(page.getByRole('button', { name: 'Enable SAST' })).toBeVisible()

  expect(problems).toEqual([])
})

test('turning SAST on shows the installed module', async ({ page, server }) => {
  const problems = watch(page)
  const stub = await stubSAST(page, {
    enabled: false,
    state: 'not_installed',
    version: 'v1.33.1',
    installing: false,
  })
  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await page.getByRole('button', { name: 'Enable SAST' }).click()

  const card = page.getByRole('region', { name: 'SAST' })
  await expect(card).toContainText('On')
  await expect(card).toContainText('v1.33.1')
  await expect(card.getByRole('button', { name: 'Off' })).toBeVisible()
  expect(stub.puts).toEqual([true])

  expect(problems).toEqual([])
})
