import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useMemo } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { trendQuery } from '../../api/reports'
import { EmptyState } from '../../components/empty-state'
import { formatNumber, useT } from '../../lib/i18n'
import {
  aggregateTrend,
  latestTrendRow,
  trendDayLabel,
  trendDayTitle,
  trendSeverities,
  type TrendSeverity,
} from '../../lib/report-trend'
import { reportTrendDays, type ReportSearch } from '../../lib/urls'
import { cn } from '../../lib/utils'
import {
  ReportCaption,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  type ReportPanelProps,
} from './shared'

/** defaultTrendDays is the API's default window, shown as the selected option. */
const defaultTrendDays = 90

/**
 * severityColors paint the chart from the theme tokens, so light and dark mode
 * both read correctly without a second palette.
 */
const severityColors: Record<TrendSeverity, string> = {
  critical: 'var(--b-critical)',
  high: 'var(--b-high)',
  medium: 'var(--b-medium)',
  low: 'var(--b-low)',
  unknown: 'var(--b-border-strong)',
}

/**
 * TrendReport is the Trend over time report (#190): open findings per day by
 * severity, stacked. With every project in scope the series are summed into one
 * fleet-wide area chart; a project picked in the band narrows the same chart.
 */
export function TrendReport({ search }: ReportPanelProps) {
  const t = useT()
  const navigate = useNavigate()
  const days = search.days ?? defaultTrendDays
  const trend = useQuery(trendQuery({ assetId: search.asset, days }))
  const rows = useMemo(
    () => aggregateTrend(trend.data?.series ?? []),
    [trend.data],
  )

  function changeDays(next: number) {
    const value = next as (typeof reportTrendDays)[number]
    const nextSearch: ReportSearch = { ...search }
    if (value === defaultTrendDays) delete nextSearch.days
    else nextSearch.days = value
    void navigate({
      to: '/reports/$reportId',
      params: { reportId: 'trend' },
      search: nextSearch,
      replace: true,
    })
  }

  if (trend.isPending) return <ReportLoading />
  if (trend.isError) return <ReportError error={trend.error} />

  if (rows.length === 0) {
    return (
      <EmptyState
        title={t('reports.trend.empty.title')}
        body={t('reports.trend.empty.body')}
      />
    )
  }

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-col gap-1">
          <ReportPanelHeading title={t('reports.trend.chart.title')} />
          <ReportCaption>{t('reports.trend.caption')}</ReportCaption>
        </div>
        <div
          role="group"
          aria-label={t('reports.trend.days.aria')}
          className="flex items-center gap-1 rounded-md border border-border-subtle bg-bg p-0.5"
        >
          {reportTrendDays.map((option) => {
            const active = days === option
            return (
              <button
                key={option}
                type="button"
                aria-pressed={active}
                onClick={() => changeDays(option)}
                className={cn(
                  'rounded px-2.5 py-1 text-[0.8125rem] transition-colors',
                  active
                    ? 'bg-surface text-fg shadow-sm'
                    : 'text-muted hover:text-fg',
                )}
              >
                {t('reports.trend.days.option', { days: option })}
              </button>
            )
          })}
        </div>
      </div>

      <div className="rounded-card border border-border-subtle bg-surface p-4 sm:p-5">
        <div
          role="img"
          aria-label={t('reports.trend.chart.aria')}
          className="h-72 w-full sm:h-80"
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={rows}
              margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
            >
              <defs>
                {trendSeverities.map((severity) => (
                  <linearGradient
                    key={severity}
                    id={`trend-${severity}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor={severityColors[severity]}
                      stopOpacity={0.34}
                    />
                    <stop
                      offset="100%"
                      stopColor={severityColors[severity]}
                      stopOpacity={0.04}
                    />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="var(--b-border-subtle)"
                vertical={false}
              />
              <XAxis
                dataKey="date"
                tickFormatter={trendDayLabel}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
                tickMargin={8}
                tick={{ fill: 'var(--b-faint)', fontSize: 11 }}
              />
              <YAxis
                allowDecimals={false}
                width={40}
                tickLine={false}
                axisLine={false}
                tickMargin={4}
                tick={{ fill: 'var(--b-faint)', fontSize: 11 }}
              />
              <Tooltip
                cursor={{ stroke: 'var(--b-border-strong)', strokeWidth: 1 }}
                labelFormatter={(label) => trendDayTitle(String(label))}
                wrapperStyle={{ outline: 'none' }}
                contentStyle={{
                  background: 'var(--b-surface)',
                  border: '1px solid var(--b-border-subtle)',
                  borderRadius: 8,
                  boxShadow: '0 8px 24px rgb(0 0 0 / 0.12)',
                  color: 'var(--b-fg)',
                  fontSize: 12,
                  padding: '6px 10px',
                }}
                labelStyle={{ color: 'var(--b-muted)', marginBottom: 4 }}
                itemStyle={{ color: 'var(--b-fg)', padding: '1px 0' }}
              />
              {trendSeverities.map((severity) => (
                <Area
                  key={severity}
                  type="monotone"
                  dataKey={severity}
                  stackId="severity"
                  name={t(`severity.${severity}`)}
                  stroke={severityColors[severity]}
                  strokeWidth={1.5}
                  fill={`url(#trend-${severity})`}
                  activeDot={{
                    r: 3,
                    strokeWidth: 0,
                    fill: severityColors[severity],
                  }}
                  animationDuration={220}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <TrendLegend rows={rows} />
      </div>
    </section>
  )
}

/** TrendLegend is the chart's key, with the newest day's count per severity. */
function TrendLegend({
  rows,
}: {
  rows: ReturnType<typeof aggregateTrend>
}) {
  const t = useT()
  const latest = latestTrendRow(rows)
  if (latest === undefined) return null

  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-border-subtle pt-3">
      <ul aria-label={t('reports.trend.legend.aria')} className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
        {trendSeverities.map((severity) => (
          <li
            key={severity}
            className="flex items-center gap-1.5 text-xs text-muted"
          >
            <span
              aria-hidden="true"
              className="size-2 rounded-full"
              style={{ background: severityColors[severity] }}
            />
            <span>{t(`severity.${severity}`)}</span>
            <span className="font-semibold text-fg tabular-nums">
              {formatNumber(latest[severity])}
            </span>
          </li>
        ))}
      </ul>
      <p className="flex items-center gap-2 text-xs text-muted">
        <span>{t('reports.trend.latest', { date: trendDayTitle(latest.date) })}</span>
        <span className="font-semibold text-fg tabular-nums">
          {t('reports.trend.total', { count: latest.total })}
        </span>
      </p>
    </div>
  )
}
