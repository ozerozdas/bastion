import { describe, expect, it } from 'vitest'

import {
  isHttpsUrl,
  parseAssetSearch,
  parseConfigurationsTab,
  parseConnectionsTab,
  parseFindingsSearch,
  parseProjectsTabSearch,
  parseReportSearch,
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

  it('keeps a trimmed text search in the URL', () => {
    expect(parseFindingsSearch({ q: '  CVE-2026-0001  ' })).toEqual({
      q: 'CVE-2026-0001',
    })
    expect(parseFindingsSearch({ q: '   ' })).toEqual({})
    expect(parseFindingsSearch({ q: 7 })).toEqual({})
    expect(parseFindingsSearch({ q: ['cve'] })).toEqual({})
  })

  it('caps the search at the length the API accepts', () => {
    expect(parseFindingsSearch({ q: 'a'.repeat(250) })).toEqual({
      q: 'a'.repeat(200),
    })
  })

  it('keeps the search with a view or a page', () => {
    expect(parseFindingsSearch({ view: 'single', q: 'cve' })).toEqual({
      view: 'single',
      q: 'cve',
    })
    expect(parseFindingsSearch({ q: 'cve', page: '3' })).toEqual({
      page: 3,
      q: 'cve',
    })
  })

  it('drops the search on the fix plan tab, which is not the findings list', () => {
    expect(parseFindingsSearch({ tab: 'fix-plan', q: 'cve' })).toEqual({
      tab: 'fix-plan',
    })
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

describe('parseConfigurationsTab', () => {
  it('keeps a named section so the URL stays copyable and reload-safe', () => {
    for (const tab of ['policies', 'notifications', 'ai', 'mcp', 'appearance'] as const) {
      expect(parseConfigurationsTab({ tab })).toEqual({ tab })
    }
  })

  it('treats the default Modules tab as the bare path', () => {
    expect(parseConfigurationsTab({})).toEqual({})
    expect(parseConfigurationsTab({ tab: undefined })).toEqual({})
    expect(parseConfigurationsTab({ tab: 'modules' })).toEqual({})
  })

  it('drops an unknown tab instead of showing an empty panel', () => {
    expect(parseConfigurationsTab({ tab: 'docker' })).toEqual({})
    expect(parseConfigurationsTab({ tab: 1 })).toEqual({})
    expect(parseConfigurationsTab({ tab: ['ai'] })).toEqual({})
  })
})

describe('parseReportSearch', () => {
  it('keeps the project, the advisory and an offered trend window', () => {
    expect(
      parseReportSearch({ asset: '7', cve: ' CVE-2021-44228 ', days: '365' }),
    ).toEqual({ asset: 7, cve: 'CVE-2021-44228', days: 365 })
  })

  it('keeps only the windows the trend report offers', () => {
    expect(parseReportSearch({ days: '30' })).toEqual({ days: 30 })
    expect(parseReportSearch({ days: '45' })).toEqual({})
    expect(parseReportSearch({ days: 'abc' })).toEqual({})
  })

  it('drops a blank advisory and malformed ids instead of failing the route', () => {
    expect(parseReportSearch({ cve: '   ' })).toEqual({})
    expect(parseReportSearch({ cve: 7 })).toEqual({})
    expect(parseReportSearch({ asset: 'abc', cve: 'GHSA-jfh8-c2jp-5v3q' })).toEqual({
      cve: 'GHSA-jfh8-c2jp-5v3q',
    })
  })

  it('caps a pasted advisory id', () => {
    const cve = 'C'.repeat(100)
    expect(parseReportSearch({ cve })).toEqual({ cve: 'C'.repeat(64) })
  })
})
