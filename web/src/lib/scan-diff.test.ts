import { describe, expect, it } from 'vitest'

import type { Scan } from '../api/scans'
import {
  compareBaselines,
  diffGroupEmptyText,
  parseScanIdParam,
  scanDiffSubtitle,
} from './scan-diff'

const scan = (id: number, status: Scan['status']): Scan => ({
  id,
  asset_id: 1,
  status,
  trigger: 'cli',
  counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
})

describe('parseScanIdParam', () => {
  it('reads a positive integer scan id', () => {
    expect(parseScanIdParam('7')).toBe(7)
    expect(parseScanIdParam('1234')).toBe(1234)
  })

  it('rejects anything that names no scan', () => {
    expect(parseScanIdParam('0')).toBeUndefined()
    expect(parseScanIdParam('-1')).toBeUndefined()
    expect(parseScanIdParam('1.5')).toBeUndefined()
    expect(parseScanIdParam('abc')).toBeUndefined()
    expect(parseScanIdParam('')).toBeUndefined()
  })
})

describe('scanDiffSubtitle', () => {
  it('names the scan compared with', () => {
    expect(scanDiffSubtitle(3)).toBe('compared with scan #3')
  })

  it('explains a first scan has nothing to compare with', () => {
    expect(scanDiffSubtitle(undefined)).toBe(
      'first scan — nothing to compare, every finding is new',
    )
  })
})

describe('compareBaselines', () => {
  it('keeps the other succeeded scans, newest first as the API returns them', () => {
    const scans = [
      scan(9, 'succeeded'),
      scan(8, 'running'),
      scan(7, 'succeeded'),
      scan(6, 'failed'),
      scan(5, 'succeeded'),
    ]
    expect(compareBaselines(scans, 7).map((entry) => entry.id)).toEqual([9, 5])
  })

  it('never offers the scan on screen', () => {
    expect(compareBaselines([scan(4, 'succeeded')], 4)).toEqual([])
  })

  it('has nothing to offer when the asset has one succeeded scan', () => {
    expect(
      compareBaselines([scan(4, 'succeeded'), scan(3, 'queued')], 4),
    ).toEqual([])
  })
})

describe('diffGroupEmptyText', () => {
  it('gives each empty group its own line', () => {
    const lines = (['new', 'fixed', 'persisting'] as const).map(
      diffGroupEmptyText,
    )
    expect(new Set(lines).size).toBe(3)
    for (const line of lines) expect(line.length).toBeGreaterThan(0)
  })
})
