import { describe, expect, it } from 'vitest'

import { exportFindingsUrl, filterParams, findingStateBatches } from './findings'

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

describe('exportFindingsUrl', () => {
  it('carries the format and view with no filters', () => {
    expect(exportFindingsUrl({ format: 'csv', view: 'grouped' })).toBe(
      '/api/findings/export?format=csv&view=grouped',
    )
  })

  it('repeats the list filters before the format and view', () => {
    expect(
      exportFindingsUrl({
        assetId: 7,
        type: 'secret',
        severity: 'high',
        status: 'open',
        format: 'xlsx',
        view: 'single',
      }),
    ).toBe(
      '/api/findings/export?asset_id=7&type=secret&severity=high&status=open&format=xlsx&view=single',
    )
  })
})

describe('findingStateBatches', () => {
  it('returns nothing for an empty selection', () => {
    expect(findingStateBatches([])).toEqual([])
  })

  it('puts a single asset selection in one batch', () => {
    expect(
      findingStateBatches([
        { assetId: 7, fingerprint: 'fp-1' },
        { assetId: 7, fingerprint: 'fp-2' },
      ]),
    ).toEqual([{ assetId: 7, fingerprints: ['fp-1', 'fp-2'] }])
  })

  it('groups a cross-project selection by asset, in selection order', () => {
    expect(
      findingStateBatches([
        { assetId: 2, fingerprint: 'fp-beta' },
        { assetId: 1, fingerprint: 'fp-alpha' },
        { assetId: 2, fingerprint: 'fp-beta-2' },
      ]),
    ).toEqual([
      { assetId: 2, fingerprints: ['fp-beta', 'fp-beta-2'] },
      { assetId: 1, fingerprints: ['fp-alpha'] },
    ])
  })
})
