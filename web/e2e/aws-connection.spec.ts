import type { Page } from '@playwright/test'

import { expect, test, watch } from './fixtures'

const awsConnection = {
  id: 1,
  kind: 'aws',
  name: 'prod',
  status: 'ok',
  profile: 'work',
  region: 'eu-central-1',
  account: '123456789012',
  arn: 'arn:aws:iam::123456789012:user/bastion-test',
  created_at: '2026-11-15T10:00:00Z',
  last_checked_at: '2026-11-15T10:00:01Z',
  ecr_asset_count: 2,
}

/**
 * fakeConnectionsApi serves the AWS connection list and its mutations from
 * in-test state. No AWS call is made: the server-side test is mocked here.
 */
async function fakeConnectionsApi(page: Page, created: unknown = awsConnection) {
  let connections: unknown[] = []

  await page.route('**/api/connections', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ connections }),
      })
    }
    connections = [created]
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify(created),
    })
  })

  await page.route('**/api/connections/1/test', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(created),
    }),
  )

  await page.route('**/api/connections/1', (route) => {
    if (route.request().method() === 'PATCH') {
      const { name } = route.request().postDataJSON() as { name: string }
      connections = [{ ...awsConnection, name }]
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(connections[0]),
      })
    }
    connections = []
    return route.fulfill({ status: 204, body: '' })
  })
}

/** fakeDockerApi hides the Docker card so the page has one registry source. */
async function fakeDockerApi(page: Page) {
  await page.route('**/api/docker/images', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ available: false, host: '', images: [] }),
    }),
  )
}

test('AWS connections are created, tested and removed on the Registry tab', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  await fakeConnectionsApi(page)
  await fakeDockerApi(page)

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Connections', exact: true }).click()
  await page.getByRole('tab', { name: 'Registry' }).click()

  await expect(page.getByText('No AWS connection yet')).toBeVisible()
  await page.getByRole('button', { name: 'New connection' }).click()

  const createRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/connections') &&
      request.method() === 'POST',
  )

  await page.getByLabel('Name').fill('prod')
  await page.getByLabel('Profile').fill('work')
  await page.getByLabel('Region').fill('eu-central-1')
  await page.getByRole('button', { name: 'Add connection' }).click()

  // The form sends only the profile and region: no AWS credential.
  expect((await createRequest).postDataJSON()).toEqual({
    kind: 'aws',
    name: 'prod',
    profile: 'work',
    region: 'eu-central-1',
  })

  // The row shows what STS reported, and the form reports the account.
  await expect(
    page.getByText('123456789012', { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText('arn:aws:iam::123456789012:user/bastion-test'),
  ).toBeVisible()
  // A working connection closes the dialog; the card is the confirmation.
  await expect(page.getByRole('dialog')).toBeHidden()

  // Rename edits the name in place: Enter commits and sends only the name.
  await page.getByRole('button', { name: 'Actions for prod' }).click()
  await page.getByRole('menuitem', { name: 'Rename' }).click()
  const renameRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith('/api/connections/1') &&
      request.method() === 'PATCH',
  )
  await page.getByLabel('Connection name').fill('production')
  await page.keyboard.press('Enter')
  expect((await renameRequest).postDataJSON()).toEqual({ name: 'production' })
  await expect(page.getByText('production', { exact: true })).toBeVisible()

  const actions = page.getByRole('button', { name: 'Actions for production' })
  await actions.click()
  await page.getByRole('menuitem', { name: 'Test' }).click()
  await expect(actions).toBeEnabled()

  await actions.click()
  await page.getByRole('menuitem', { name: 'Remove' }).click()
  await expect(
    page.getByText('Only the profile and region are forgotten'),
  ).toBeVisible()
  await expect(
    page.getByText(
      'This also archives 2 ECR images and hides their findings.',
    ),
  ).toBeVisible()
  await page.getByRole('button', { name: 'Remove', exact: true }).click()

  await expect(page.getByText('No AWS connection yet')).toBeVisible()
  expect(problems).toEqual([])
})

test('a failed AWS test shows the hint, not a credential', async ({
  page,
  server,
}) => {
  const problems = watch(page)
  const failed = {
    ...awsConnection,
    status: 'error',
    account: undefined,
    arn: undefined,
    hint: 'AWS rejected the credentials (ExpiredToken); refresh the AWS session and test again',
  }
  await fakeConnectionsApi(page, failed)
  await fakeDockerApi(page)

  await page.goto(server.url)
  await page.getByRole('link', { name: 'Connections', exact: true }).click()
  await page.getByRole('tab', { name: 'Registry' }).click()
  await page.getByRole('button', { name: 'New connection' }).click()

  await page.getByLabel('Name').fill('prod')
  await page.getByLabel('Region').fill('eu-central-1')
  await page.getByRole('button', { name: 'Add connection' }).click()

  await expect(
    page.getByText('Connection saved, but the test failed.'),
  ).toBeVisible()
  await expect(page.getByText(/ExpiredToken/).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Actions for prod' })).toBeAttached()
  expect(problems).toEqual([])
})
