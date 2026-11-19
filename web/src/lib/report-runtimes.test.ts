import { describe, expect, it } from 'vitest'

import { eolDaysLeft, eolStatus } from './report-runtimes'

/** Midday UTC, so a timezone shift cannot move the test's "today". */
const now = Date.UTC(2026, 10, 19, 12)

describe('eolStatus', () => {
  it('marks a date already behind us as past', () => {
    expect(eolStatus('2026-11-18', now)).toBe('past')
    expect(eolStatus('2020-01-01', now)).toBe('past')
  })

  it('warns under 90 days away, including today', () => {
    expect(eolStatus('2026-11-19', now)).toBe('soon')
    expect(eolStatus('2027-02-15', now)).toBe('soon')
  })

  it('treats 90 days away and beyond as supported', () => {
    expect(eolStatus('2027-02-17', now)).toBe('ok')
    expect(eolStatus('2030-01-01', now)).toBe('ok')
  })

  it('has no verdict without a usable date', () => {
    expect(eolStatus(null, now)).toBe('unknown')
    expect(eolStatus('not-a-date', now)).toBe('unknown')
  })
})

describe('eolDaysLeft', () => {
  it('counts whole days from today', () => {
    expect(eolDaysLeft('2026-11-19', now)).toBe(0)
    expect(eolDaysLeft('2026-11-29', now)).toBe(10)
    expect(eolDaysLeft('2026-11-09', now)).toBe(-10)
  })

  it('is null without a usable date', () => {
    expect(eolDaysLeft(null, now)).toBeNull()
    expect(eolDaysLeft('soon', now)).toBeNull()
  })
})
