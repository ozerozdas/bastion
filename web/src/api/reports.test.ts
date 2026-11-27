import { describe, expect, it } from 'vitest'

import { snapshotFormats, snapshotUrl } from './reports'

describe('snapshotUrl', () => {
  it('builds the fleet-wide URL from the format alone', () => {
    expect(snapshotUrl('md')).toBe('/api/reports/snapshot?format=md')
  })

  it('adds the asset id when one project is selected', () => {
    expect(snapshotUrl('html', 7)).toBe(
      '/api/reports/snapshot?format=html&asset_id=7',
    )
  })

  it('accepts every format the selector offers', () => {
    for (const format of snapshotFormats) {
      expect(snapshotUrl(format)).toBe(`/api/reports/snapshot?format=${format}`)
    }
  })
})
