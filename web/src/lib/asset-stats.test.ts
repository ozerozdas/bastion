import { describe, expect, it } from 'vitest'

import type { Asset } from '../api/assets'
import { assetStats } from './asset-stats'

/** asset builds the fields assetStats reads, with the rest filled in. */
function asset(overrides: Partial<Asset>): Asset {
  return {
    id: 1,
    kind: 'repo',
    display_name: 'acme/api',
    ref: 'acme/api',
    created_at: '2026-11-01T10:00:00Z',
    scan_schedule: 'off',
    open_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    linked_images: [],
    ...overrides,
  }
}

describe('assetStats', () => {
  it('counts daily and weekly schedules only', () => {
    const stats = assetStats([
      asset({ id: 1, scan_schedule: 'daily' }),
      asset({ id: 2, scan_schedule: 'weekly' }),
      asset({ id: 3, scan_schedule: 'off' }),
    ])
    expect(stats.scheduled).toBe(2)
  })

  it('sums open findings across assets', () => {
    const stats = assetStats([
      asset({
        id: 1,
        open_counts: { critical: 1, high: 2, medium: 3, low: 4, unknown: 5 },
      }),
      asset({
        id: 2,
        open_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      }),
    ])
    expect(stats.open).toEqual({ critical: 2, high: 2, medium: 3, low: 4, unknown: 5 })
  })

  it('keeps the newest finished scan and ignores unfinished ones', () => {
    const stats = assetStats([
      asset({
        id: 1,
        last_scan: { scan_id: 1, status: 'succeeded', finished_at: '2026-11-01T10:00:00Z' },
      }),
      asset({
        id: 2,
        last_scan: { scan_id: 2, status: 'succeeded', finished_at: '2026-11-10T10:00:00Z' },
      }),
      asset({ id: 3, last_scan: { scan_id: 3, status: 'running' } }),
    ])
    expect(stats.lastScan).toBe('2026-11-10T10:00:00Z')
  })

  it('has no last scan when nothing finished', () => {
    expect(assetStats([]).lastScan).toBeUndefined()
  })
})
