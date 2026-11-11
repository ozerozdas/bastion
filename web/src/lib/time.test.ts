import { describe, expect, it } from 'vitest'

import { scanDuration, relativeTime } from './time'

const now = Date.parse('2026-05-01T12:00:00Z')
const at = (offsetMs: number) => new Date(now + offsetMs).toISOString()

// Intl output is locale-dependent, so expectations are built with the same
// formatters the UI uses rather than hard-coded English strings.
const relative = (value: number, unit: Intl.RelativeTimeFormatUnit) =>
  new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(value, unit)

const absolute = (timestamp: string) =>
  new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp))

describe('relativeTime', () => {
  it('says a scan has not started when the timestamp is absent', () => {
    expect(relativeTime(undefined, now)).toBe('not started')
  })

  it('does not crash on an unparsable timestamp', () => {
    expect(relativeTime('yesterday-ish', now)).toBe('unknown')
  })

  it('collapses the last minute to "just now"', () => {
    expect(relativeTime(at(-10_000), now)).toBe('just now')
    expect(relativeTime(at(10_000), now)).toBe('just now')
  })

  it('rounds to the nearest minute, hour and day', () => {
    expect(relativeTime(at(-5 * 60_000), now)).toBe(relative(-5, 'minute'))
    expect(relativeTime(at(-2 * 3_600_000), now)).toBe(relative(-2, 'hour'))
    expect(relativeTime(at(-3 * 86_400_000), now)).toBe(relative(-3, 'day'))
  })

  it('falls back to the full date beyond a month', () => {
    const old = at(-40 * 86_400_000)
    expect(relativeTime(old, now)).toBe(absolute(old))
  })
})

describe('scanDuration', () => {
  it('waits for a queued scan without a start time', () => {
    expect(scanDuration({ status: 'queued' })).toBe('waiting')
  })

  it('says a running scan is running', () => {
    expect(scanDuration({ status: 'running', started_at: at(-5_000) })).toBe(
      'running',
    )
  })

  it('shows a dash for a scan that never started and is not queued', () => {
    expect(scanDuration({ status: 'failed' })).toBe('—')
  })

  it('phrases seconds, minutes and hours', () => {
    expect(
      scanDuration({ status: 'succeeded', started_at: at(0), finished_at: at(0) }),
    ).toBe('0s')
    expect(
      scanDuration({
        status: 'succeeded',
        started_at: at(0),
        finished_at: at(42_000),
      }),
    ).toBe('42s')
    expect(
      scanDuration({
        status: 'succeeded',
        started_at: at(0),
        finished_at: at(90_000),
      }),
    ).toBe('1m 30s')
    expect(
      scanDuration({
        status: 'succeeded',
        started_at: at(0),
        finished_at: at(3_661_000),
      }),
    ).toBe('1h 1m')
  })

  it('never shows a negative duration', () => {
    expect(
      scanDuration({
        status: 'failed',
        started_at: at(1_000),
        finished_at: at(0),
      }),
    ).toBe('0s')
  })

  it('shows a dash when a finished scan has an unparsable start', () => {
    expect(
      scanDuration({
        status: 'succeeded',
        started_at: 'not-a-date',
        finished_at: at(0),
      }),
    ).toBe('—')
  })
})
