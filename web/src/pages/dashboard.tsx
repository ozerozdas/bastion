import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState, useSyncExternalStore } from 'react'

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
import { PageActions } from '../components/app-shell'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { InfoTip } from '../components/ui/info-tip'
import {
  getStartedState,
  isCliStepDone,
  isGetStartedDismissed,
  type GetStartedState,
  type GetStartedStep,
} from '../lib/get-started'
import { useT } from '../lib/i18n'
import {
  cliDonePreference,
  dismissedPreference,
  setPreference,
  subscribePreferences,
} from '../lib/preferences'
import { formatDateTime, relativeTime } from '../lib/time'

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
          <GetStartedStrip
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

  return (
    <div className="flex flex-col gap-6">
      {checklist?.visible === true ? (
        <GetStartedStrip
          state={checklist}
          onDismiss={dismissChecklist}
          onCliDone={markCliStep}
        />
      ) : null}
      <PageActions>
        <LatestScan scans={data.last_scans} />
      </PageActions>
      <RiskSummary totals={data.totals_by_severity} />
      <RiskiestProjects assets={data.top_assets} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <FindingsByType totals={data.totals_by_type} />
        <Trend trends={data.trend} names={names} />
      </div>
      <LastScans scans={data.last_scans} />
    </div>
  )
}

/** LatestScan says in the page header when the newest scan finished, or that one is running. */
function LatestScan({ scans }: { scans: LastScan[] }) {
  const t = useT()
  if (scans.some((s) => s.status === 'queued' || s.status === 'running')) {
    return <span className="text-xs text-muted">{t('dashboard.header.scanning')}</span>
  }
  // ISO timestamps sort as strings.
  const newest = scans
    .map((s) => s.finished_at)
    .filter((f): f is string => f !== undefined)
    .sort()
    .at(-1)
  if (!newest) {
    return null
  }
  return (
    <span className="text-xs text-faint tabular-nums" title={formatDateTime(newest)}>
      {t('dashboard.header.lastScan', { when: relativeTime(newest) })}
    </span>
  )
}

// Same frame as RiskSummary so every dashboard block reads as its own card.
const CARD = 'rounded-card border border-border-subtle bg-surface px-4 py-3.5'

/** SectionHeading names a block and carries its secondary explanation. */
function SectionHeading({
  id,
  title,
  tip,
}: {
  id: string
  title: string
  tip?: { label: string; content: string }
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <h2 id={id} className="text-[0.8125rem] font-semibold">
        {title}
      </h2>
      {tip === undefined ? null : (
        <InfoTip label={tip.label} content={tip.content} />
      )}
    </div>
  )
}

/**
 * GetStartedStrip is the checklist as one line: progress, the next open step,
 * and a disclosure with every step's own action when it is needed.
 */
function GetStartedStrip({
  state,
  onDismiss,
  onCliDone,
}: {
  state: GetStartedState
  onDismiss: () => void
  onCliDone: () => void
}) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const next = state.steps.find((step) => !step.done)
  const percent = Math.round((state.doneCount / state.total) * 100)
  const linkClass =
    'underline underline-offset-2 hover:text-accent'
  return (
    <section
      aria-labelledby="get-started-heading"
      className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface px-4 py-2.5"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 id="get-started-heading" className="text-[0.8125rem] font-semibold">
          {t('dashboard.getStarted.title')}
        </h2>
        <span className="flex items-center gap-2 text-xs text-muted">
          <span
            aria-hidden="true"
            className="h-1 w-16 overflow-hidden rounded-full bg-hover"
          >
            <span
              className="block h-1 rounded-full bg-ok"
              style={{ width: `${String(percent)}%` }}
            />
          </span>
          <span className="tabular-nums">
            {t('dashboard.getStarted.progress', {
              done: state.doneCount,
              total: state.total,
            })}
          </span>
        </span>
        {next === undefined ? null : (
          <span className="text-xs text-muted">
            {t('dashboard.getStarted.next')}{' '}
            <GetStartedStepLink
              step={next}
              onCliDone={onCliDone}
              className={`text-[0.8125rem] ${linkClass}`}
            />
          </span>
        )}
        <div className="ml-auto flex items-center gap-1">
          <Button
            type="button"
            size="sm"
            variant="ghost"
            aria-expanded={open}
            onClick={() => setOpen((shown) => !shown)}
          >
            {t('dashboard.getStarted.steps')}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onDismiss}>
            {t('dashboard.getStarted.dismiss')}
          </Button>
        </div>
      </div>
      {open ? (
        <ol className="flex flex-col gap-2.5 border-t border-border-subtle pt-2.5">
          {state.steps.map((step, index) => (
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
                  <GetStartedStepLink
                    step={step}
                    onCliDone={onCliDone}
                    className={`text-[0.8125rem] ${linkClass}`}
                  />
                  {step.done ? (
                    <Badge tone="ok">{t('dashboard.getStarted.done')}</Badge>
                  ) : null}
                </div>
                <p className="text-xs text-muted">{step.hint}</p>
              </div>
            </li>
          ))}
        </ol>
      ) : null}
    </section>
  )
}

/** GetStartedStepLink keeps each step's own action: a route or the CLI docs. */
function GetStartedStepLink({
  step,
  onCliDone,
  className,
}: {
  step: GetStartedStep
  onCliDone: () => void
  className: string
}) {
  if (step.href !== undefined) {
    return (
      <a
        href={step.href}
        target="_blank"
        rel="noreferrer"
        onClick={onCliDone}
        className={className}
      >
        {step.title}
      </a>
    )
  }
  if (step.to !== undefined) {
    return (
      <Link to={step.to} className={className}>
        {step.title}
      </Link>
    )
  }
  return <span className={className}>{step.title}</span>
}

/**
 * RiskSummary is the dashboard hero: the total and a one-line verdict on the
 * left, the per-severity breakdown on the right, and one segmented bar that
 * shows the mix at a glance.
 */
function RiskSummary({ totals }: { totals: SeverityTotals }) {
  const t = useT()
  const total = openFindingTotal(totals)
  const rows = [
    { key: 'critical', count: totals.critical, label: t('severity.critical'), mark: 'bg-critical', strong: true },
    { key: 'high', count: totals.high, label: t('severity.high'), mark: 'bg-high', strong: true },
    { key: 'medium', count: totals.medium, label: t('severity.medium'), mark: 'bg-medium', strong: false },
    { key: 'low', count: totals.low, label: t('severity.low'), mark: 'bg-low', strong: false },
    { key: 'unknown', count: totals.unknown, label: t('severity.unknown'), mark: 'bg-border-strong', strong: false },
  ].filter((r) => r.key !== 'unknown' || r.count > 0)
  return (
    <section
      aria-labelledby="severity-heading"
      className="flex flex-col gap-5 rounded-card border border-border-subtle bg-surface px-5 py-5 sm:px-6"
    >
      <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex flex-col gap-2">
          <SectionHeading
            id="severity-heading"
            title={t('dashboard.openFindings')}
            tip={{
              label: t('dashboard.openFindings.scopeAria'),
              content: t('dashboard.openFindings.scope', { total }),
            }}
          />
          <div className="flex items-baseline gap-3">
            <span className="text-[2.5rem] leading-none font-semibold tracking-tight tabular-nums">
              {total}
            </span>
            <Link to="/findings" className="text-[0.8125rem] text-muted hover:text-fg hover:underline">
              {t('dashboard.hero.viewAll')}
            </Link>
          </div>
          <p className="text-[0.8125rem] text-muted">
            {t('dashboard.hero.headline', { critical: totals.critical, high: totals.high })}
          </p>
        </div>
        <ul className="grid grid-cols-2 gap-2 sm:grid-cols-5 lg:w-[34rem]">
          {rows.map((r) => (
            <li
              key={r.key}
              className={`flex flex-col gap-1.5 rounded-md px-3 py-2.5 ${r.strong ? 'bg-hover' : ''}`}
            >
              <span
                className={`leading-none tabular-nums ${
                  r.strong ? 'text-[1.5rem] font-semibold' : 'text-[1.125rem] font-medium text-muted'
                }`}
              >
                {r.count}
              </span>
              <span className="flex items-center gap-1.5 text-xs text-muted">
                <span aria-hidden="true" className={`size-1.5 rounded-full ${r.mark}`} />
                {r.label}
              </span>
            </li>
          ))}
        </ul>
      </div>
      {total > 0 ? (
        <div aria-hidden="true" className="flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full">
          {rows.map((r) =>
            r.count > 0 ? (
              <span key={r.key} className={r.mark} style={{ flexGrow: r.count }} />
            ) : null,
          )}
        </div>
      ) : null}
    </section>
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
    <section aria-labelledby="by-type-heading" className={`flex flex-col gap-3 ${CARD}`}>
      <SectionHeading id="by-type-heading" title={t('dashboard.byType.title')} />
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

/** RiskiestProjects is the top five by score, as compact full-width rows. */
function RiskiestProjects({ assets }: { assets: AssetRisk[] }) {
  const t = useT()
  return (
    <section aria-labelledby="riskiest-heading" className={`flex flex-col gap-2 ${CARD}`}>
      <SectionHeading
        id="riskiest-heading"
        title={t('dashboard.riskiest.title')}
        tip={{
          label: t('dashboard.riskiest.aria'),
          content: t('dashboard.riskiest.subtitle'),
        }}
      />
      {assets.length === 0 ? (
        <p className="text-xs text-muted">{t('dashboard.riskiest.empty')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[0.875rem]">
            <thead className="text-xs text-faint">
              <tr>
                <th className="w-full border-b border-border-subtle pb-1.5 font-medium">
                  {t('dashboard.column.project')}
                </th>
                <th className="border-b border-border-subtle pb-1.5 pl-4 text-right font-medium">
                  {t('dashboard.column.score')}
                </th>
                <th className="border-b border-border-subtle pb-1.5 pl-4 font-medium whitespace-nowrap">
                  {t('severity.critical')}
                </th>
                <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium whitespace-nowrap">
                  {t('severity.high')}
                </th>
                <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium whitespace-nowrap sm:table-cell">
                  {t('severity.medium')}
                </th>
                <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium whitespace-nowrap sm:table-cell">
                  {t('severity.low')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {assets.map((asset) => (
                <tr key={asset.asset_id} className="hover:bg-hover">
                  <td className="w-full max-w-0 py-1.5 pr-3">
                    <Link
                      to="/findings"
                      search={{ asset: asset.asset_id }}
                      className="block truncate hover:underline"
                      title={`${asset.kind}: ${asset.display_name}`}
                    >
                      {asset.display_name}
                    </Link>
                  </td>
                  <td className="py-1.5 pl-4 text-right text-muted tabular-nums">
                    {asset.score}
                  </td>
                  <td className="py-1.5 pl-4 whitespace-nowrap">
                    <CountBadge count={asset.critical} tone="critical" />
                  </td>
                  <td className="py-1.5 pl-3 whitespace-nowrap">
                    <CountBadge count={asset.high} tone="high" />
                  </td>
                  <td className="hidden py-1.5 pl-3 whitespace-nowrap sm:table-cell">
                    <CountBadge count={asset.medium} tone="medium" />
                  </td>
                  <td className="hidden py-1.5 pl-3 whitespace-nowrap sm:table-cell">
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

/** Trend plots each project's open critical and high count, newest scan last. */
function Trend({
  trends,
  names,
}: {
  trends: AssetTrend[]
  names: Map<number, string>
}) {
  const t = useT()
  return (
    <section aria-labelledby="trend-heading" className={`flex flex-col gap-3 ${CARD}`}>
      <SectionHeading
        id="trend-heading"
        title={t('dashboard.trend.title')}
        tip={{
          label: t('dashboard.trend.aria'),
          content: t('dashboard.trend.body'),
        }}
      />
      {trends.length === 0 ? (
        <p className="text-xs text-muted">{t('dashboard.trend.empty')}</p>
      ) : (
        <ul className="flex flex-col divide-y divide-border-subtle">
          {trends.map((trend) => {
            const name =
              names.get(trend.asset_id) ??
              t('asset.fallback', { id: trend.asset_id })
            return (
              <li
                key={trend.asset_id}
                // No negative margin: it pushed the row 8px past the grid
                // column, so the dashboard grid scrolled sideways at 1440.
                className="flex items-center justify-between gap-4 rounded py-1.5 hover:bg-hover"
              >
                <Link
                  to="/findings"
                  search={{ asset: trend.asset_id }}
                  title={name}
                  className="min-w-0 truncate text-[0.875rem] hover:underline"
                >
                  {name}
                </Link>
                <div className="flex shrink-0 items-center gap-3">
                  <span className="whitespace-nowrap text-xs text-faint tabular-nums">
                    {t('dashboard.trend.open', {
                      count: trend.scans.at(-1)?.critical_high_open ?? 0,
                    })}
                  </span>
                  <Sparkline trend={trend} label={name} />
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

/** LastScans shows the newest scan of every project and how it ended. */
function LastScans({ scans }: { scans: LastScan[] }) {
  const t = useT()
  return (
    <section aria-labelledby="last-scans-heading" className={`flex flex-col gap-2 ${CARD}`}>
      <SectionHeading
        id="last-scans-heading"
        title={t('dashboard.lastScans.title')}
        tip={{
          label: t('dashboard.lastScans.aria'),
          content: t('dashboard.lastScans.subtitle'),
        }}
      />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[0.8125rem]">
          <thead className="text-xs text-faint">
            <tr>
              <th className="border-b border-border-subtle pb-1.5 font-medium">
                {t('dashboard.column.project')}
              </th>
              <th className="status-cell border-b border-border-subtle pb-1.5 font-medium">
                {t('dashboard.column.status')}
              </th>
              <th className="hidden border-b border-border-subtle pb-1.5 text-right font-medium sm:table-cell">
                {t('dashboard.column.lastScan')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {scans.map((scan) => {
              const status = statusView[scan.status]
              return (
                <tr key={scan.asset_id} className="hover:bg-hover">
                  <td className="w-full max-w-0 py-1.5 pr-3">
                    <Link
                      to="/findings"
                      search={{ asset: scan.asset_id }}
                      className="block truncate hover:underline"
                      title={scan.display_name}
                    >
                      {scan.display_name}
                    </Link>
                  </td>
                  <td className="status-cell py-1.5 pr-3">
                    <Badge tone={status.tone}>{t(status.labelKey)}</Badge>
                  </td>
                  <td
                    className="hidden py-1.5 text-right whitespace-nowrap text-muted tabular-nums sm:table-cell"
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
