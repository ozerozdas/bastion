import { describe, expect, it } from 'vitest'

import { suggestFix } from './hints'

describe('suggestFix', () => {
  it('points a token or 401 failure at the connection test', () => {
    expect(suggestFix('github: bad credentials (401)')).toBe(
      'Re-test the GitHub connection on Connections.',
    )
    expect(suggestFix('missing token')).toBe(
      'Re-test the GitHub connection on Connections.',
    )
  })

  it('tells the user to wait out a rate limit', () => {
    expect(suggestFix('API rate limit exceeded')).toBe(
      'Wait until GitHub resets the rate limit, then scan again.',
    )
  })

  it('treats not found as a permissions problem', () => {
    expect(suggestFix('repository not found')).toBe(
      'Check the token has access to this repository.',
    )
    expect(suggestFix('HTTP 404')).toBe(
      'Check the token has access to this repository.',
    )
  })

  it('falls back to the Scans tab for anything else', () => {
    expect(suggestFix('gitleaks: exit status 1')).toBe(
      'See the Scans tab under Projects for details.',
    )
    expect(suggestFix(undefined)).toBe(
      'See the Scans tab under Projects for details.',
    )
  })
})
