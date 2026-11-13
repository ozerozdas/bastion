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

  it('treats the default Projects tab as the bare path', () => {
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
