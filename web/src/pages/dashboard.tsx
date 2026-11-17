import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useSyncExternalStore } from 'react'

import { assetsQuery } from '../api/assets'
import { ApiError } from '../api/client'
import { connectionsQuery } from '../api/connections'
import {
  dashboardQuery,
  openFindingTotal,
  type AssetRisk,
  type AssetTrend,
  type LastScan,
  type SeverityTotals,
  type TypeTotals,
} from '../api/reports'
import { scansQuery } from '../api/scans'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import {
  getStartedState,
  isCliStepDone,
  isGetStartedDismissed,
  type GetStartedState,
} from '../lib/get-started'
import { useT } from '../lib/i18n'
import {
  cliDonePreference,
  dismissedPreference,
  setPreference,
  subscribePreferences,
} from '../lib/preferences'
import { formatDateTime, relativeTime } from '../lib/time'

/** severityTiles is the fixed order of the four severity totals (§7.1). */
const severityTiles: {
  key: keyof SeverityTotals
  labelKey: string
  mark: string
}[] = [
  { key: 'critical', labelKey: 'severity.critical', mark: 'bg-critical' },
  { key: 'high', labelKey: 'severity.high', mark: 'bg-high' },
  { key: 'medium', labelKey: 'severity.medium', mark: 'bg-medium' },
  { key: 'low', labelKey: 'severity.low', mark: 'bg-low' },
]

/** typeLabels maps the API's type keys to the words shown in the UI. */
const typeLabels: { key: keyof TypeTotals; labelKey: string }[] = [
  { key: 'vulnerability', labelKey: 'type.plural.vulnerability' },
  { key: 'secret', labelKey: 'type.plural.secret' },
  { key: 'outdated', labelKey: 'type.plural.outdated' },
  { key: 'misconfig', labelKey: 'type.plural.misconfig' },
  { key: 'license', labelKey: 'type.plural.license' },
  { key: 'malware', labelKey: 'type.plural.malware' },
  { key: 'sast', labelKey: 'type.plural.sast' },
]

/** statusView maps a scan status to its badge text and tone. */
const statusView: Record<
  LastScan['status'],
  { tone: 'neutral' | 'ok' | 'critical'; labelKey: string }
> = {
  queued: { tone: 'neutral', labelKey: 'scanStatus.queued' },
  running: { tone: 'neutral', labelKey: 'scanStatus.running' },
  succeeded: { tone: 'ok', labelKey: 'scanStatus.succeeded' },
  failed: { tone: 'critical', labelKey: 'scanStatus.failed' },
  canceled: { tone: 'neutral', labelKey: 'scanStatus.canceled' },
}

export function DashboardPage() {
  const t = useT()
  const dashboard = useQuery(dashboardQuery)
  const connections = useQuery(connectionsQuery)
  const assets = useQuery(assetsQuery)
  const scans = useQuery(scansQuery())
  // The dismissals live in localStorage and on the server (#150); subscribing
  // makes a value that arrives from the startup fetch re-render the card.
  const cliDone = useSyncExternalStore(subscribePreferences, () =>
    isCliStepDone(window.localStorage),
  )
  const dismissed = useSyncExternalStore(subscribePreferences, () =>
    isGetStartedDismissed(window.localStorage),
  )

  // The checklist reads only data these three queries already return; while one
  // is still loading the card waits rather than flashing open steps.
  const checklist =
    connections.isSuccess && assets.isSuccess && scans.isSuccess
      ? getStartedState({
          connectionCount: connections.data.length,
          assetCount: assets.data.length,
          hasSucceededScan: scans.data.some(
            (scan) => scan.status === 'succeeded',
          ),
          cliDone,
          dismissed,
        })
      : undefined

  const dismissChecklist = () => {
    setPreference(dismissedPreference, '1')
  }

  const markCliStep = () => {
    setPreference(cliDonePreference, '1')
  }

  if (dashboard.status === 'pending') {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">{t('dashboard.loading')}</p>
      </section>
    )
  }

  if (dashboard.status === 'error') {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[0.8125rem] font-semibold">
          {t('dashboard.failed')}
        </h2>
        <ErrorNote error={dashboard.error} />
      </section>
    )
  }

  const data = dashboard.data

  // last_scans holds an entry for every asset that has ever been scanned, so an
  // empty list means there is nothing to aggregate yet: explain the next step.
  if (data.last_scans.length === 0) {
    return (
      <>
        {checklist?.visible === true ? (
          <GetStartedCard
            state={checklist}
            onDismiss={dismissChecklist}
            onCliDone={markCliStep}
          />
        ) : null}
        <EmptyState
          title={t('dashboard.noScans.title')}
          body={t('dashboard.noScans.body')}
        >
          {checklist === undefined || checklist.visible ? null : (
            <>
              <Link to="/connections" className={buttonVariants()}>
                {t('dashboard.connectGithub')}
              </Link>
              <Link
                to="/repositories"
                className={buttonVariants({ variant: 'outline' })}
              >
                {t('dashboard.addLocalPath')}
              </Link>
            </>
          )}
        </EmptyState>
      </>
    )
  }

  const names = assetNames(data.last_scans, data.top_assets)
  const total = openFindingTotal(data.totals_by_severity)

  return (
    <>
      {checklist?.visible === true ? (
        <GetStartedCard
          state={checklist}
          onDismiss={dismissChecklist}
          onCliDone={markCliStep}
        />
      ) : null}
      <section
        aria-labelledby="severity-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 id="severity-heading" className="text-[0.8125rem] font-semibold">
            {t('dashboard.openFindings')}
          </h2>
          <span className="text-faint">
            {t('dashboard.openFindings.scope', { total })}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-5">
          {severityTiles.map((tile) => (
            <SeverityTile
              key={tile.key}
              count={data.totals_by_severity[tile.key]}
              label={t(tile.labelKey)}
              mark={tile.mark}
            />
          ))}
          {data.totals_by_severity.unknown > 0 ? (
            <SeverityTile
              count={data.totals_by_severity.unknown}
              label={t('severity.unknown')}
              mark="bg-border-strong"
            />
          ) : null}
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <FindingsByType totals={data.totals_by_type} />
        <RiskiestAssets assets={data.top_assets} />
      </div>

      <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
        <div className="flex flex-col gap-0.5">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('dashboard.trend.title')}
          </h2>
          <p className="text-xs text-muted">{t('dashboard.trend.body')}</p>
        </div>
        {data.trend.length === 0 ? (
          <p className="text-xs text-muted">{t('dashboard.trend.empty')}</p>
        ) : (
          <ul className="flex flex-col divide-y divide-border-subtle">
            {data.trend.map((trend) => (
              <li
                key={trend.asset_id}
                className="-mx-2 flex items-center justify-between gap-4 rounded px-2 py-2 hover:bg-hover"
              >
                <Link
                  to="/findings"
                  search={{ asset: trend.asset_id }}
                  className="truncate text-[0.8125rem] hover:underline"
                >
                  {names.get(trend.asset_id) ??
                    t('asset.fallback', { id: trend.asset_id })}
                </Link>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-faint tabular-nums">
                    {t('dashboard.trend.open', {
                      count: trend.scans.at(-1)?.critical_high_open ?? 0,
                    })}
                  </span>
                  <Sparkline
                    trend={trend}
                    label={
                      names.get(trend.asset_id) ??
                      t('asset.fallback', { id: trend.asset_id })
                    }
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('dashboard.lastScans.title')}
          </h2>
          <span className="text-faint">{t('dashboard.lastScans.subtitle')}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[0.8125rem]">
            <thead className="text-xs text-faint">
              <tr>
                <th className="pb-2 font-medium">
                  {t('dashboard.column.project')}
                </th>
                <th className="status-cell pb-2 font-medium">
                  {t('dashboard.column.status')}
                </th>
                <th className="pb-2 text-right font-medium">
                  {t('dashboard.column.lastScan')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {data.last_scans.map((scan) => {
                const status = statusView[scan.status]
                return (
                  <tr key={scan.asset_id} className="hover:bg-hover">
                    <td className="py-2 pr-3">
                      <Link
                        to="/findings"
                        search={{ asset: scan.asset_id }}
                        className="hover:underline"
                      >
                        {scan.display_name}
                      </Link>
                    </td>
                    <td className="status-cell py-2 pr-3">
                      <Badge tone={status.tone}>{t(status.labelKey)}</Badge>
                    </td>
                    <td
                      className="py-2 text-right whitespace-nowrap text-muted tabular-nums"
                      title={
                        scan.finished_at
                          ? formatDateTime(scan.finished_at)
                          : undefined
                      }
                    >
                      {scan.finished_at
                        ? relativeTime(scan.finished_at)
                        : t('dashboard.notFinished')}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

/** GetStartedCard is the four-step checklist; each step links to where it is done. */
function GetStartedCard({
  state,
  onDismiss,
  onCliDone,
}: {
  state: GetStartedState
  onDismiss: () => void
  onCliDone: () => void
}) {
  const t = useT()
  return (
    <section
      aria-labelledby="get-started-heading"
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <h2 id="get-started-heading" className="text-[0.8125rem] font-semibold">
            {t('dashboard.getStarted.title')}
          </h2>
          <p className="text-xs text-muted">
            {t('dashboard.getStarted.body', {
              done: state.doneCount,
              total: state.total,
            })}
          </p>
        </div>
        <Button type="button" size="sm" variant="ghost" onClick={onDismiss}>
          {t('dashboard.getStarted.dismiss')}
        </Button>
      </div>
      <ol className="flex flex-col gap-2.5">
        {state.steps.map((step, index) => {
          const titleClass =
            'text-[0.8125rem] underline underline-offset-2 hover:text-accent'
          return (
            <li key={step.id} className="flex items-start gap-2.5">
              <span
                aria-hidden="true"
                className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[0.6875rem] tabular-nums ${
                  step.done
                    ? 'border-ok/30 bg-ok/10 text-ok'
                    : 'border-border-strong text-muted'
                }`}
              >
                {step.done ? '✓' : String(index + 1)}
              </span>
              <div className="flex min-w-0 flex-col gap-0.5">
                <div className="flex flex-wrap items-center gap-2">
                  {step.href ? (
                    <a
                      href={step.href}
                      target="_blank"
                      rel="noreferrer"
                      onClick={onCliDone}
                      className={titleClass}
                    >
                      {step.title}
                    </a>
                  ) : step.to ? (
                    <Link to={step.to} className={titleClass}>
                      {step.title}
                    </Link>
                  ) : (
                    <span className="text-[0.8125rem]">{step.title}</span>
                  )}
                  {step.done ? (
                    <Badge tone="ok">{t('dashboard.getStarted.done')}</Badge>
                  ) : null}
                </div>
                <p className="text-xs text-muted">{step.hint}</p>
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

/** SeverityTile is one calm number with a small severity mark (§7). */
function SeverityTile({
  count,
  label,
  mark,
}: {
  count: number
  label: string
  mark: string
}) {
  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border-subtle bg-bg px-3 py-2.5">
      <span className="flex items-center gap-1.5 text-xs text-muted">
        <span aria-hidden="true" className={`size-1.5 rounded-full ${mark}`} />
        {label}
      </span>
      <span className="text-xl font-semibold tabular-nums">{count}</span>
    </div>
  )
}

/** FindingsByType lists open findings per type with a proportional bar. */
function FindingsByType({ totals }: { totals: TypeTotals }) {
  const t = useT()
  const rows = typeLabels
    .map((row) => ({ ...row, count: totals[row.key] }))
    .filter((row) => row.count > 0)
  const max = Math.max(1, ...rows.map((row) => row.count))

  return (
    <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
      <h2 className="text-[0.8125rem] font-semibold">
        {t('dashboard.byType.title')}
      </h2>
      {rows.length === 0 ? (
        <p className="text-xs text-muted">{t('dashboard.byType.empty')}</p>
      ) : (
        <ul className="flex flex-col gap-2.5">
          {rows.map((row) => (
            <li key={row.key} className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between gap-3">
                <span className="flex items-baseline gap-2 text-[0.8125rem]">
                  {t(row.labelKey)}
                  {row.key === 'license' ? (
                    <span className="text-xs text-faint">
                      {t('dashboard.byType.informational')}
                    </span>
                  ) : null}
                </span>
                <span className="text-xs text-muted tabular-nums">{row.count}</span>
              </div>
              <div aria-hidden="true" className="h-1 w-full rounded-full bg-hover">
                <div
                  className="h-1 rounded-full bg-accent/60"
                  style={{ width: `${String((row.count / max) * 100)}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/** RiskiestAssets is the top five by score, with per-severity counts. */
function RiskiestAssets({ assets }: { assets: AssetRisk[] }) {
  const t = useT()
  return (
    <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
      <div className="flex flex-wrap items-baseline gap-2.5">
        <h2 className="text-[0.8125rem] font-semibold">
          {t('dashboard.riskiest.title')}
        </h2>
        <span className="text-faint">{t('dashboard.riskiest.subtitle')}</span>
      </div>
      {assets.length === 0 ? (
        <p className="text-xs text-muted">{t('dashboard.riskiest.empty')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[0.8125rem]">
            <thead className="text-xs text-faint">
              <tr>
                <th className="pb-2 font-medium">
                  {t('dashboard.column.project')}
                </th>
                <th className="pb-2 text-right font-medium">
                  {t('dashboard.column.score')}
                </th>
                <th className="pb-2 pl-3 font-medium">
                  {t('severity.critical')}
                </th>
                <th className="pb-2 pl-2 font-medium">{t('severity.high')}</th>
                <th className="pb-2 pl-2 font-medium">
                  {t('severity.medium')}
                </th>
                <th className="pb-2 pl-2 font-medium">{t('severity.low')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {assets.map((asset) => (
                <tr key={asset.asset_id} className="hover:bg-hover">
                  <td className="py-2 pr-3">
                    <Link
                      to="/findings"
                      search={{ asset: asset.asset_id }}
                      className="hover:underline"
                      title={`${asset.kind}: ${asset.display_name}`}
                    >
                      {asset.display_name}
                    </Link>
                  </td>
                  <td className="py-2 text-right text-muted tabular-nums">{asset.score}</td>
                  <td className="py-2 pl-3">
                    <CountBadge count={asset.critical} tone="critical" />
                  </td>
                  <td className="py-2 pl-2">
                    <CountBadge count={asset.high} tone="high" />
                  </td>
                  <td className="py-2 pl-2">
                    <CountBadge count={asset.medium} tone="medium" />
                  </td>
                  <td className="py-2 pl-2">
                    <CountBadge count={asset.low} tone="low" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

/** CountBadge keeps severity colour on the badge and greys out zero counts. */
function CountBadge({
  count,
  tone,
}: {
  count: number
  tone: 'critical' | 'high' | 'medium' | 'low'
}) {
  if (count === 0) {
    return <span className="text-xs text-faint tabular-nums">0</span>
  }
  return (
    <Badge tone={tone} className="tabular-nums">
      {count}
    </Badge>
  )
}

/**
 * Sparkline draws the critical+high series with plain SVG. It is decorative
 * only up to its accessible title; there is no chart library for one polyline.
 */
function Sparkline({ trend, label }: { trend: AssetTrend; label: string }) {
  const t = useT()
  const values = trend.scans.map((scan) => scan.critical_high_open)
  const width = 96
  const height = 24
  const pad = 2.5
  const max = Math.max(...values, 1)
  const step = values.length > 1 ? (width - pad * 2) / (values.length - 1) : 0
  const points = values.map((value, index) => ({
    x: pad + index * step,
    y: height - pad - (value / max) * (height - pad * 2),
  }))
  const summary = values.join(', ')
  const title = t('dashboard.sparkline', {
    label,
    count: values.length,
    scans: t('dashboard.sparkline.scans', { count: values.length }),
    values: summary,
  })

  return (
    <svg
      role="img"
      aria-label={title}
      width={width}
      height={height}
      viewBox={`0 0 ${String(width)} ${String(height)}`}
      className="shrink-0 text-critical"
    >
      <title>{title}</title>
      {points.length === 1 ? (
        <circle
          cx={points[0]?.x ?? width / 2}
          cy={points[0]?.y ?? height / 2}
          r={2}
          fill="currentColor"
        />
      ) : (
        <polyline
          points={points.map((point) => `${String(point.x)},${String(point.y)}`).join(' ')}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  )
}

/** assetNames joins trend rows (asset_id only) to a human name. */
function assetNames(
  lastScans: LastScan[],
  assets: AssetRisk[],
): Map<number, string> {
  const names = new Map<number, string>()
  for (const asset of assets) {
    names.set(asset.asset_id, asset.display_name)
  }
  for (const scan of lastScans) {
    names.set(scan.asset_id, scan.display_name)
  }
  return names
}

/** ErrorNote shows the problem detail the API returned, plus what to do next. */
function ErrorNote({ error }: { error: unknown }) {
  const t = useT()
  const cause =
    error instanceof ApiError
      ? `${error.message}${error.problem?.title ? ` (${error.problem.title})` : ''}`
      : error instanceof Error
        ? error.message
        : t('common.requestFailed')

  return (
    <p role="alert" className="text-xs text-critical">
      {cause} <span className="text-muted">{t('common.reloadFix')}</span>
    </p>
  )
}
