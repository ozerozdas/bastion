import { describe, expect, it } from 'vitest'

import { filterParams } from './findings'

describe('filterParams', () => {
  it('returns an empty string when nothing is filtered', () => {
    expect(filterParams({})).toBe('')
  })

  it('keeps asset 0, which is a valid id to filter on', () => {
    expect(filterParams({ assetId: 0 })).toBe('?asset_id=0')
  })

  it('includes every set filter in query order', () => {
    expect(
      filterParams({
        assetId: 7,
        type: 'secret',
        severity: 'high',
        status: 'open',
      }),
    ).toBe('?asset_id=7&type=secret&severity=high&status=open')
  })

  it('skips unset filters', () => {
    expect(filterParams({ severity: 'critical' })).toBe('?severity=critical')
  })
})
