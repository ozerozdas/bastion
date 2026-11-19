import { describe, expect, it } from 'vitest'

import type { ReportTrendSeries } from '../api/reports'
import { aggregateTrend, latestTrendRow, trendPointTotal } from './report-trend'

function series(
  assetId: number,
  name: string,
  points: ReportTrendSeries['points'],
): ReportTrendSeries {
  return { asset_id: assetId, display_name: name, points }
}

describe('aggregateTrend', () => {
  it('sums every project into one row per day', () => {
    const rows = aggregateTrend([
      series(1, 'api', [
        {
          date: '2026-11-10',
          critical: 1,
          high: 2,
          medium: 3,
          low: 0,
          unknown: 0,
        },
        {
          date: '2026-11-11',
          critical: 2,
          high: 0,
          medium: 0,
          low: 1,
          unknown: 0,
        },
      ]),
      series(2, 'web', [
        {
          date: '2026-11-10',
          critical: 0,
          high: 1,
          medium: 4,
          low: 0,
          unknown: 1,
        },
        {
          date: '2026-11-11',
          critical: 0,
          high: 3,
          medium: 1,
          low: 0,
          unknown: 0,
        },
      ]),
    ])

    expect(rows).toEqual([
      {
        date: '2026-11-10',
        critical: 1,
        high: 3,
        medium: 7,
        low: 0,
        unknown: 1,
        total: 12,
      },
      {
        date: '2026-11-11',
        critical: 2,
        high: 3,
        medium: 1,
        low: 1,
        unknown: 0,
        total: 7,
      },
    ])
  })

  it('keeps a day only one project scanned and sorts the days', () => {
    const rows = aggregateTrend([
      series(1, 'b', [
        { date: '2026-11-12', critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      ]),
      series(2, 'a', [
        { date: '2026-11-10', critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
      ]),
    ])

    expect(rows.map((row) => row.date)).toEqual(['2026-11-10', '2026-11-12'])
  })

  it('is empty when no project has a point', () => {
    expect(aggregateTrend([])).toEqual([])
    expect(aggregateTrend([series(1, 'api', [])])).toEqual([])
    expect(latestTrendRow([])).toBeUndefined()
  })
})

describe('trendPointTotal', () => {
  it('counts every severity of one point', () => {
    expect(
      trendPointTotal({
        date: '2026-11-10',
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
        unknown: 5,
      }),
    ).toBe(15)
  })
})
