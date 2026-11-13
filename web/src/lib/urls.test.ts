import { describe, expect, it } from 'vitest'

import { isHttpsUrl, parseAssetSearch } from './urls'

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
