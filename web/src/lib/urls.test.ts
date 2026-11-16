import { describe, expect, it } from 'vitest'

import {
  isHttpsUrl,
  parseAssetSearch,
  parseConnectionsTab,
  parseFindingsSearch,
  parseProjectsTabSearch,
  parseScanDiffSearch,
} from './urls'

describe('isHttpsUrl', () => {
  it('accepts https references, ignoring case and surrounding space', () => {
    expect(isHttpsUrl('https://github.com/advisories/GHSA-1')).toBe(true)
    expect(isHttpsUrl('  HTTPS://example.com/CVE-2026-1  ')).toBe(true)
  })

  it('rejects plain http and other schemes', () => {
    expect(isHttpsUrl('http://example.com')).toBe(false)
    expect(isHttpsUrl('javascript:alert(1)')).toBe(false)
    expect(isHttpsUrl('file:///etc/passwd')).toBe(false)
    expect(isHttpsUrl('/relative/path')).toBe(false)
    expect(isHttpsUrl('')).toBe(false)
  })
})

describe('parseAssetSearch', () => {
  it('keeps a positive integer id, as a number or a query-string string', () => {
    expect(parseAssetSearch({ asset: 7 })).toEqual({ asset: 7 })
    expect(parseAssetSearch({ asset: '7' })).toEqual({ asset: 7 })
  })

  it('keeps the old route\'s handling of zero', () => {
    expect(parseAssetSearch({ asset: 0 })).toEqual({})
    expect(parseAssetSearch({ asset: '0' })).toEqual({ asset: 0 })
  })

  it('drops a missing or malformed id, so the page falls back to all projects', () => {
    expect(parseAssetSearch({})).toEqual({})
    expect(parseAssetSearch({ asset: undefined })).toEqual({})
    expect(parseAssetSearch({ asset: -1 })).toEqual({})
    expect(parseAssetSearch({ asset: '-1' })).toEqual({})
    expect(parseAssetSearch({ asset: 1.5 })).toEqual({})
    expect(parseAssetSearch({ asset: '1.5' })).toEqual({})
    expect(parseAssetSearch({ asset: 'abc' })).toEqual({})
    expect(parseAssetSearch({ asset: ['7'] })).toEqual({})
  })
})

describe('parseFindingsSearch', () => {
  it('treats grouped as the default, so it is the bare path (#106)', () => {
    expect(parseFindingsSearch({})).toEqual({})
    expect(parseFindingsSearch({ view: undefined })).toEqual({})
    expect(parseFindingsSearch({ view: 'grouped' })).toEqual({})
  })

  it('keeps view=single so opting out survives a reload', () => {
    expect(parseFindingsSearch({ view: 'single' })).toEqual({ view: 'single' })
  })

  it('drops an unknown view instead of failing the route', () => {
    expect(parseFindingsSearch({ view: 'grid' })).toEqual({})
    expect(parseFindingsSearch({ view: ['single'] })).toEqual({})
  })

  it('keeps the project filter and ignores the view with it (#106)', () => {
    expect(parseFindingsSearch({ view: 'single', asset: '7' })).toEqual({
      asset: 7,
    })
    expect(parseFindingsSearch({ view: 'single', asset: 'x' })).toEqual({
      view: 'single',
    })
    expect(parseFindingsSearch({ asset: '7' })).toEqual({ asset: 7 })
  })

  it('keeps the fix plan tab and the project it belongs to (#27)', () => {
    expect(parseFindingsSearch({ tab: 'fix-plan' })).toEqual({
      tab: 'fix-plan',
    })
    expect(parseFindingsSearch({ tab: 'fix-plan', asset: '7' })).toEqual({
      tab: 'fix-plan',
      asset: 7,
    })
  })

  it('drops an unknown tab instead of hiding the findings list', () => {
    expect(parseFindingsSearch({ tab: 'plan' })).toEqual({})
  })

  it('keeps a page above 1 and an offered page size', () => {
    expect(parseFindingsSearch({ page: '3', size: '100' })).toEqual({
      page: 3,
      size: 100,
    })
    expect(parseFindingsSearch({ page: 2, size: 25 })).toEqual({
      page: 2,
      size: 25,
    })
  })

  it('keeps page and size with a view or a project', () => {
    expect(parseFindingsSearch({ view: 'single', page: '2' })).toEqual({
      view: 'single',
      page: 2,
    })
    expect(parseFindingsSearch({ asset: '7', size: '200' })).toEqual({
      asset: 7,
      size: 200,
    })
  })

  it('drops page 1, the default size and values the pager cannot offer', () => {
    expect(parseFindingsSearch({ page: '1', size: '50' })).toEqual({})
    expect(parseFindingsSearch({ page: '0' })).toEqual({})
    expect(parseFindingsSearch({ page: '-1' })).toEqual({})
    expect(parseFindingsSearch({ size: '75' })).toEqual({})
    expect(parseFindingsSearch({ size: 'abc' })).toEqual({})
  })

  it('does not page the fix plan, which is per project', () => {
    expect(parseFindingsSearch({ tab: 'fix-plan', page: '3', size: '25' })).toEqual(
      { tab: 'fix-plan' },
    )
  })
})

describe('parseScanDiffSearch', () => {
  it('keeps a positive baseline scan, as a number or a query-string string', () => {
    expect(parseScanDiffSearch({ against: 7 })).toEqual({ against: 7 })
    expect(parseScanDiffSearch({ against: '7' })).toEqual({ against: 7 })
  })

  it('treats a missing baseline as the previous succeeded scan', () => {
    expect(parseScanDiffSearch({})).toEqual({})
    expect(parseScanDiffSearch({ against: undefined })).toEqual({})
  })

  it('drops a malformed id instead of failing the route', () => {
    expect(parseScanDiffSearch({ against: 0 })).toEqual({})
    expect(parseScanDiffSearch({ against: '0' })).toEqual({})
    expect(parseScanDiffSearch({ against: -1 })).toEqual({})
    expect(parseScanDiffSearch({ against: '-1' })).toEqual({})
    expect(parseScanDiffSearch({ against: 1.5 })).toEqual({})
    expect(parseScanDiffSearch({ against: '1.5' })).toEqual({})
    expect(parseScanDiffSearch({ against: 'abc' })).toEqual({})
    expect(parseScanDiffSearch({ against: ['7'] })).toEqual({})
  })
})

describe('parseProjectsTabSearch', () => {
  it('keeps the Scans tab so the URL stays copyable and reload-safe', () => {
    expect(parseProjectsTabSearch({ tab: 'scans' })).toEqual({ tab: 'scans' })
  })

  it('treats the default Repositories tab as the bare path', () => {
    expect(parseProjectsTabSearch({})).toEqual({})
    expect(parseProjectsTabSearch({ tab: undefined })).toEqual({})
    expect(parseProjectsTabSearch({ tab: 'projects' })).toEqual({})
  })

  it('drops an unknown tab instead of hiding the project list', () => {
    expect(parseProjectsTabSearch({ tab: 'history' })).toEqual({})
    expect(parseProjectsTabSearch({ tab: 1 })).toEqual({})
    expect(parseProjectsTabSearch({ tab: ['scans'] })).toEqual({})
  })

  it('keeps the Scans project filter only on the Scans tab (#54)', () => {
    expect(parseProjectsTabSearch({ tab: 'scans', asset: '7' })).toEqual({
      tab: 'scans',
      asset: 7,
    })
    expect(parseProjectsTabSearch({ tab: 'scans', asset: 'x' })).toEqual({
      tab: 'scans',
    })
    expect(parseProjectsTabSearch({ asset: 7 })).toEqual({})
  })
})

describe('parseConnectionsTab', () => {
  it('keeps the Registry tab so the URL stays copyable and reload-safe', () => {
    expect(parseConnectionsTab({ tab: 'registry' })).toEqual({
      tab: 'registry',
    })
  })

  it('treats the default Repository tab as the bare path', () => {
    expect(parseConnectionsTab({})).toEqual({})
    expect(parseConnectionsTab({ tab: undefined })).toEqual({})
    expect(parseConnectionsTab({ tab: 'repository' })).toEqual({})
  })

  it('drops an unknown tab instead of hiding the GitHub setup', () => {
    expect(parseConnectionsTab({ tab: 'docker' })).toEqual({})
    expect(parseConnectionsTab({ tab: 1 })).toEqual({})
    expect(parseConnectionsTab({ tab: ['registry'] })).toEqual({})
  })
})
