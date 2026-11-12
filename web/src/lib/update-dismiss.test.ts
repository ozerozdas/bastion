import { describe, expect, it } from 'vitest'

import {
  dismissUpdate,
  isUpdateDismissed,
  updateDismissKey,
} from './update-dismiss'

/** fakeStorage is the two localStorage methods the helper uses. */
function fakeStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial))
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value)
    },
  }
}

describe('update dismissal', () => {
  it('scopes the key to the release version', () => {
    expect(updateDismissKey('v0.1.2')).toBe('bastion:update-dismissed:v0.1.2')
    expect(updateDismissKey('v0.1.3')).not.toBe(updateDismissKey('v0.1.2'))
  })

  it('remembers one version without hiding another', () => {
    const storage = fakeStorage()
    expect(isUpdateDismissed(storage, 'v0.1.2')).toBe(false)

    dismissUpdate(storage, 'v0.1.2')

    expect(isUpdateDismissed(storage, 'v0.1.2')).toBe(true)
    expect(isUpdateDismissed(storage, 'v0.1.3')).toBe(false)
  })
})
