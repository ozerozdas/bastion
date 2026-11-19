import type {
  ReportTrendPoint,
  ReportTrendSeries,
} from '../api/reports'
import { language } from './i18n'

/** TrendSeverity is one severity the trend chart stacks. */
export type TrendSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

/** trendSeverities is the stacking order, worst at the bottom of the chart. */
export const trendSeverities: readonly TrendSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
]

/** TrendRow is one day of the chart: the summed counts and their total. */
export type TrendRow = Record<TrendSeverity, number> & {
  date: string
  total: number
}

function emptyCounts(): Record<TrendSeverity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
}

/**
 * aggregateTrend folds every series into one point per day, summing each
 * severity across projects. The overview is read fleet-wide by default, so the
 * chart must not draw one line per project. Days are sorted oldest first; the
 * API already sorts each series, but a hand-built payload may not.
 */
export function aggregateTrend(
  series: readonly ReportTrendSeries[],
): TrendRow[] {
  const byDate = new Map<string, Record<TrendSeverity, number>>()
  for (const item of series) {
    for (const point of item.points) {
      const counts = byDate.get(point.date) ?? emptyCounts()
      for (const severity of trendSeverities) {
        counts[severity] += point[severity]
      }
      byDate.set(point.date, counts)
    }
  }
  return [...byDate.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([date, counts]) => ({
      date,
      ...counts,
      total:
        counts.critical +
        counts.high +
        counts.medium +
        counts.low +
        counts.unknown,
    }))
}

/** latestTrendRow is the newest day of the chart, or undefined when it is empty. */
export function latestTrendRow(rows: readonly TrendRow[]): TrendRow | undefined {
  return rows.at(-1)
}

/** yyyyMmDd matches the API's date-only trend points. */
const yyyyMmDd = /^(\d{4})-(\d{2})-(\d{2})$/

const dayFormats = new Map<string, Intl.DateTimeFormat>()

/**
 * trendDayLabel is an axis label for a date-only point. Date-only strings parse
 * as UTC, so the formatter also reads them in UTC: otherwise a browser west of
 * Greenwich would label 2026-11-10 as the 9th.
 */
export function trendDayLabel(date: string): string {
  const match = yyyyMmDd.exec(date)
  if (match === null) return date
  const code = language()
  let format = dayFormats.get(code)
  if (format === undefined) {
    format = new Intl.DateTimeFormat(code, {
      month: 'short',
      day: 'numeric',
      timeZone: 'UTC',
    })
    dayFormats.set(code, format)
  }
  return format.format(
    new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]))),
  )
}

/** trendDayTitle is the tooltip's full date for a date-only point. */
export function trendDayTitle(date: string): string {
  const match = yyyyMmDd.exec(date)
  if (match === null) return date
  return new Intl.DateTimeFormat(language(), {
    dateStyle: 'medium',
    timeZone: 'UTC',
  }).format(
    new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]))),
  )
}

/** trendPointTotal sums one API point's severities. */
export function trendPointTotal(point: ReportTrendPoint): number {
  return (
    point.critical + point.high + point.medium + point.low + point.unknown
  )
}
