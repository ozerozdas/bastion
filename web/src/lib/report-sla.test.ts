import { describe, expect, it } from 'vitest'

import {
  parseSlaThresholds,
  slaThresholdMax,
  slaThresholdMin,
  thresholdValues,
} from './report-sla'

const valid = {
  critical: '30',
  high: '60',
  medium: '90',
  low: '180',
}

describe('parseSlaThresholds', () => {
  it('accepts whole days inside the range', () => {
    const parsed = parseSlaThresholds(valid)
    expect(parsed.errors).toEqual({})
    expect(parsed.thresholds).toEqual({
      critical: 30,
      high: 60,
      medium: 90,
      low: 180,
    })
  })

  it('trims surrounding whitespace', () => {
    expect(
      parseSlaThresholds({ ...valid, critical: ' 45 ' }).thresholds,
    ).toEqual({ critical: 45, high: 60, medium: 90, low: 180 })
  })

  it('accepts both ends of the range', () => {
    const parsed = parseSlaThresholds({
      critical: String(slaThresholdMin),
      high: String(slaThresholdMax),
      medium: '1',
      low: '3650',
    })
    expect(parsed.thresholds).toEqual({
      critical: slaThresholdMin,
      high: slaThresholdMax,
      medium: 1,
      low: 3650,
    })
  })

  it('rejects zero, values over the maximum, decimals and text', () => {
    const parsed = parseSlaThresholds({
      critical: '0',
      high: String(slaThresholdMax + 1),
      medium: '1.5',
      low: 'thirty',
    })
    expect(parsed.thresholds).toBeNull()
    expect(parsed.errors).toEqual({
      critical: true,
      high: true,
      medium: true,
      low: true,
    })
  })

  it('rejects an empty or negative field', () => {
    expect(parseSlaThresholds({ ...valid, high: '' }).errors).toEqual({ high: true })
    expect(parseSlaThresholds({ ...valid, low: '-5' }).errors).toEqual({ low: true })
  })
})

describe('thresholdValues', () => {
  it('renders thresholds as the strings the inputs hold', () => {
    expect(
      thresholdValues({ critical: 7, high: 14, medium: 30, low: 90 }),
    ).toEqual({ critical: '7', high: '14', medium: '30', low: '90' })
  })
})
