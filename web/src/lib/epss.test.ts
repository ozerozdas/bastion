import { describe, expect, it } from 'vitest'

import { epssLabel, ordinal } from './epss'

describe('ordinal', () => {
  it('uses st, nd, rd and th', () => {
    expect(ordinal(1)).toBe('1st')
    expect(ordinal(2)).toBe('2nd')
    expect(ordinal(3)).toBe('3rd')
    expect(ordinal(4)).toBe('4th')
    expect(ordinal(21)).toBe('21st')
    expect(ordinal(92)).toBe('92nd')
    expect(ordinal(100)).toBe('100th')
  })

  it('keeps the teens on th', () => {
    expect(ordinal(11)).toBe('11th')
    expect(ordinal(12)).toBe('12th')
    expect(ordinal(13)).toBe('13th')
  })
})

describe('epssLabel', () => {
  it('renders the score and its percentile', () => {
    expect(epssLabel({ score: 0.94, percentile: 0.99 })).toBe('EPSS 0.94 · 99th pct')
  })

  it('rounds the score to two decimals', () => {
    expect(epssLabel({ score: 0.99999, percentile: 1 })).toBe('EPSS 1.00 · 100th pct')
  })
})
