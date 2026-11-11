import { describe, expect, it } from 'vitest'

import { isHttpsUrl } from './urls'

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
