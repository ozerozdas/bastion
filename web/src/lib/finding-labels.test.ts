import { describe, expect, it } from 'vitest'

import { severitySummary } from './finding-labels'

describe('severitySummary', () => {
  it('spells out a scan’s counts worst first, skipping zeros', () => {
    expect(
      severitySummary({ critical: 2, high: 1, medium: 0, low: 3, unknown: 1 }),
    ).toBe('2 critical, 1 high, 3 low, 1 unknown')
  })

  it('says so when a scan recorded nothing', () => {
    expect(
      severitySummary({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }),
    ).toBe('no findings')
  })
})
