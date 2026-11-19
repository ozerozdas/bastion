import { expect, openConfiguration, test, watch } from './fixtures'

test('adds a rule and approves an agent proposal', async ({ page, server }) => {
  const problems = watch(page)
  const proposal = {
    id: 7,
    asset_id: undefined,
    path_glob: 'fixtures/*',
    state: 'false_positive',
    reason: 'sample data',
    status: 'proposed',
    created_by: 'agent',
    created_at: '2026-11-18T10:00:00.000Z',
    matched: 0,
  }
  let rules = [proposal]
  const created: unknown[] = []
  await page.route('**/api/finding-rules', async (route) => {
    if (route.request().method() === 'POST') {
      created.push(route.request().postDataJSON())
      await route.fulfill({ status: 204 })
      return
    }
    await route.fulfill({ json: { rules } })
  })
  await page.route('**/api/finding-rules/7/approve', async (route) => {
    rules = [{ ...proposal, status: 'active', matched: 3 }]
    await route.fulfill({ status: 204 })
  })

  await page.goto(server.url)
  await expect(
    page.getByRole('heading', { level: 1, name: 'Dashboard' }),
  ).toBeVisible()
  await openConfiguration(page, 'Policies')

  const card = page.getByRole('region', { name: 'Noise rules' })
  await card.getByRole('button', { name: 'Approve' }).click()
  // The approved rule moves to the rules table with its closed count.
  await expect(card.getByRole('cell', { name: '3', exact: true })).toBeVisible()

  // The add form lives in a dialog opened from the card header.
  await card.getByRole('button', { name: 'Add', exact: true }).click()
  const form = page.getByRole('dialog', { name: 'Add a rule' })
  await form.getByLabel('Path').fill('*/tests/*')
  await form.getByLabel('Reason').fill('test code')
  await form.getByRole('button', { name: 'Add rule' }).click()
  await expect.poll(() => created.length).toBe(1)
  expect(created[0]).toMatchObject({ path_glob: '*/tests/*', reason: 'test code' })

  expect(problems).toEqual([])
})
