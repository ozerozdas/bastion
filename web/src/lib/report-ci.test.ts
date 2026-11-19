import { describe, expect, it } from 'vitest'

import type { SeverityTotals } from '../api/reports'
import { runFails, severityCountAtOrAbove } from './report-ci'

function counts(overrides: Partial<SeverityTotals> = {}): SeverityTotals {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, ...overrides }
}

describe('severityCountAtOrAbove', () => {
  it('counts only critical at the critical floor', () => {
    expect(severityCountAtOrAbove(counts({ critical: 2, high: 3 }), 'critical')).toBe(2)
  })

  it('adds the severities above the floor', () => {
    expect(severityCountAtOrAbove(counts({ critical: 2, high: 3 }), 'high')).toBe(5)
    expect(
      severityCountAtOrAbove(counts({ critical: 2, high: 3, medium: 4 }), 'medium'),
    ).toBe(9)
  })

  it('leaves low and unknown out of every floor', () => {
    expect(
      severityCountAtOrAbove(counts({ low: 7, unknown: 8 }), 'medium'),
    ).toBe(0)
  })
})

describe('runFails', () => {
  it('fails anything that did not succeed, whatever the policy', () => {
    expect(runFails({ status: 'failed', counts: counts() }, 'none')).toBe(true)
    expect(runFails({ status: 'queued', counts: counts() }, 'medium')).toBe(true)
  })

  it('passes a succeeded run with the status-only policy', () => {
    expect(
      runFails({ status: 'succeeded', counts: counts({ critical: 4 }) }, 'none'),
    ).toBe(false)
  })

  it('fails on a finding at or above the chosen floor', () => {
    const run = {
      status: 'succeeded' as const,
      counts: counts({ critical: 1, medium: 2 }),
    }
    expect(runFails(run, 'critical')).toBe(true)
    expect(runFails(run, 'high')).toBe(true)
    expect(runFails(run, 'medium')).toBe(true)
  })

  it('passes below the chosen floor', () => {
    const run = {
      status: 'succeeded' as const,
      counts: counts({ medium: 3, low: 9 }),
    }
    expect(runFails(run, 'high')).toBe(false)
    expect(runFails(run, 'critical')).toBe(false)
  })
})
