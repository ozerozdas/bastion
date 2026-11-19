import type { Page } from '@playwright/test'

import { expect, openConfiguration, test, watch } from './fixtures'

type NotificationSettings = {
  enabled: boolean
  threshold: 'high' | 'critical'
  slack_enabled: boolean
  slack_configured: boolean
  email_enabled: boolean
  smtp_host: string
  smtp_port: number
  smtp_username: string
  from: string
  to: string
  email_password_configured: boolean
}

/**
 * stubNotifications keeps the e2e server's keyring out of the test: GET
 * returns in-page state, a PUT merges it, and the test-send endpoint always
 * succeeds.
 */
async function stubNotifications(page: Page, initial: NotificationSettings) {
  let state = initial
  const saved: string[] = []
  const passwords: string[] = []

  await page.route(/\/api\/notifications$/, async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({ json: state })
      return
    }
    const body = route.request().postDataJSON() as {
      enabled?: boolean
      threshold?: NotificationSettings['threshold']
      slack_enabled?: boolean
      slack_webhook?: string
      clear_slack_webhook?: boolean
      email_enabled?: boolean
      smtp_host?: string
      smtp_port?: number
      smtp_username?: string
      from?: string
      to?: string
      email_password?: string
      clear_email_password?: boolean
    }
    if (body.slack_webhook) {
      saved.push(body.slack_webhook)
      state = { ...state, slack_configured: true }
    }
    if (body.clear_slack_webhook) {
      state = { ...state, slack_configured: false }
    }
    if (body.enabled !== undefined) {
      state = { ...state, enabled: body.enabled }
    }
    if (body.threshold !== undefined) {
      state = { ...state, threshold: body.threshold }
    }
    if (body.slack_enabled !== undefined) {
      state = { ...state, slack_enabled: body.slack_enabled }
    }
    if (body.email_enabled !== undefined) {
      state = { ...state, email_enabled: body.email_enabled }
    }
    if (body.smtp_host !== undefined) {
      state = { ...state, smtp_host: body.smtp_host }
    }
    if (body.smtp_port !== undefined) {
      state = { ...state, smtp_port: body.smtp_port }
    }
    if (body.smtp_username !== undefined) {
      state = { ...state, smtp_username: body.smtp_username }
    }
    if (body.from !== undefined) {
      state = { ...state, from: body.from }
    }
    if (body.to !== undefined) {
      state = { ...state, to: body.to }
    }
    if (body.email_password) {
      passwords.push(body.email_password)
      state = { ...state, email_password_configured: true }
    }
    if (body.clear_email_password) {
      state = { ...state, email_password_configured: false }
    }
    await route.fulfill({ json: state })
  })

  await page.route(/\/api\/notifications\/test$/, async (route) => {
    await route.fulfill({ status: 204 })
  })

  return { saved, passwords }
}

test('Notifications saves a webhook and never renders the URL', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const webhook = 'https://hooks.slack.com/services/T000/B000/secret'
  const stub = await stubNotifications(page, {
    enabled: true,
    threshold: 'high',
    slack_enabled: true,
    slack_configured: false,
    email_enabled: false,
    smtp_host: '',
    smtp_port: 587,
    smtp_username: '',
    from: '',
    to: '',
    email_password_configured: false,
  })

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()

  await openConfiguration(page, 'Notifications')
  const card = page.getByRole('region', { name: 'Notifications' })
  await expect(card).toBeVisible()
  await expect(
    card.getByText('Not configured', { exact: true }).first(),
  ).toBeVisible()

  const input = card.getByLabel('Slack webhook')
  await expect(input).toHaveAttribute('type', 'password')
  await input.fill(webhook)
  await card.getByRole('button', { name: 'Save webhook' }).click()

  await expect(card.getByText('Configured', { exact: true })).toBeVisible()
  await expect(input).toHaveValue('')
  await expect(card.getByText(webhook)).toHaveCount(0)
  expect(stub.saved).toEqual([webhook])

  // The email password is write-only too: after saving it the field is empty
  // and the value never appears in the page.
  const password = card.getByLabel('SMTP password')
  await expect(password).toHaveAttribute('type', 'password')
  await password.fill('smtp-secret')
  await card.getByRole('button', { name: 'Save password' }).click()
  await expect(password).toHaveValue('')
  await expect(card.getByText('smtp-secret')).toHaveCount(0)
  expect(stub.passwords).toEqual(['smtp-secret'])

  await card.getByRole('button', { name: 'Send test' }).click()
  await expect(card.getByText('Test sent.')).toBeVisible()

  expect(problems).toEqual([])
})
