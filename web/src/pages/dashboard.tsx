import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'

import { ApiError } from '../api/client'
import {
  dashboardQuery,
  openFindingTotal,
  type AssetRisk,
  type AssetTrend,
  type LastScan,
  type SeverityTotals,
  type TypeTotals,
} from '../api/reports'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { buttonVariants } from '../components/ui/button'
import { formatDateTime, relativeTime } from '../lib/time'

/** severityTiles is the fixed order of the four severity totals (§7.1). */
const severityTiles: {
  key: keyof SeverityTotals
  label: string
  mark: string
}[] = [
  { key: 'critical', label: 'Critical', mark: 'bg-critical' },
  { key: 'high', label: 'High', mark: 'bg-high' },
  { key: 'medium', label: 'Medium', mark: 'bg-medium' },
  { key: 'low', label: 'Low', mark: 'bg-low' },
]

/** typeLabels maps the API's type keys to the words shown in the UI. */
const typeLabels: { key: keyof TypeTotals; label: string }[] = [
  { key: 'vulnerability', label: 'Vulnerabilities' },
  { key: 'secret', label: 'Secrets' },
  { key: 'outdated', label: 'Outdated packages' },
  { key: 'misconfig', label: 'Misconfigurations' },
  { key: 'license', label: 'Licenses' },
  { key: 'malware', label: 'Malware' },
  { key: 'sast', label: 'Code issues' },
]

/** statusView maps a scan status to its badge text and tone. */
const statusView: Record<
  LastScan['status'],
  { tone: 'neutral' | 'ok' | 'critical'; label: string }
> = {
  queued: { tone: 'neutral', label: 'queued' },
  running: { tone: 'neutral', label: 'running' },
  succeeded: { tone: 'ok', label: 'succeeded' },
  failed: { tone: 'critical', label: 'failed' },
  canceled: { tone: 'neutral', label: 'canceled' },
}

export function DashboardPage() {
  const dashboard = useQuery(dashboardQuery)

  if (dashboard.status === 'pending') {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">Loading dashboard…</p>
      </section>
    )
  }

  if (dashboard.status === 'error') {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[13px] font-semibold">Dashboard failed to load</h2>
        <ErrorNote error={dashboard.error} />
      </section>
    )
  }

  const data = dashboard.data

  // last_scans holds an entry for every asset that has ever been scanned, so an
  // empty list means there is nothing to aggregate yet: explain the next step.
  if (data.last_scans.length === 0) {
    return (
      <EmptyState
        title="No scans yet"
        body="Connect GitHub or add a local path in Projects, then run a scan. Totals by severity, findings by type and the trend of open critical and high findings appear here after the first run."
      >
        <Link to="/connections" className={buttonVariants()}>
          Connect GitHub
        </Link>
        <Link to="/projects" className={buttonVariants({ variant: 'outline' })}>
          Add a local path
        </Link>
      </EmptyState>
    )
  }

  const names = assetNames(data.last_scans, data.top_assets)
  const total = openFindingTotal(data.totals_by_severity)

  return (
    <>
      <section
        aria-labelledby="severity-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 id="severity-heading" className="text-[13px] font-semibold">
            Open findings
          </h2>
          <span className="text-faint">
            {total} across each project&rsquo;s latest succeeded scan
          </span>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-5">
          {severityTiles.map((tile) => (
            <SeverityTile
              key={tile.key}
              count={data.totals_by_severity[tile.key]}
              label={tile.label}
              mark={tile.mark}
            />
          ))}
          {data.totals_by_severity.unknown > 0 ? (
            <SeverityTile
              count={data.totals_by_severity.unknown}
              label="Unknown"
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
          <h2 className="text-[13px] font-semibold">Open critical and high</h2>
          <p className="text-xs text-muted">
            Up to the last ten succeeded scans per project, oldest first.
          </p>
        </div>
        {data.trend.length === 0 ? (
          <p className="text-xs text-muted">No succeeded scans to plot yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-border-subtle">
            {data.trend.map((trend) => (
              <li
                key={trend.asset_id}
                className="flex items-center justify-between gap-4 py-2 first:pt-0 last:pb-0"
              >
                <span className="truncate text-[13px]">
                  {names.get(trend.asset_id) ?? `Asset ${String(trend.asset_id)}`}
                </span>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-faint tabular-nums">
                    {trend.scans.at(-1)?.critical_high_open ?? 0} open
                  </span>
                  <Sparkline
                    trend={trend}
                    label={
                      names.get(trend.asset_id) ??
                      `Asset ${String(trend.asset_id)}`
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
          <h2 className="text-[13px] font-semibold">Last scan per project</h2>
          <span className="text-faint">Newest scan of each project, whatever its status</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="text-xs text-faint">
              <tr>
                <th className="pb-2 font-medium">Project</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 text-right font-medium">Last scan</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {data.last_scans.map((scan) => {
                const status = statusView[scan.status]
                return (
                  <tr key={scan.asset_id}>
                    <td className="py-2 pr-3">{scan.display_name}</td>
                    <td className="py-2 pr-3">
                      <Badge tone={status.tone}>{status.label}</Badge>
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
                        : 'not finished'}
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
  const rows = typeLabels
    .map((row) => ({ ...row, count: totals[row.key] }))
    .filter((row) => row.count > 0)
  const max = Math.max(1, ...rows.map((row) => row.count))

  return (
    <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
      <h2 className="text-[13px] font-semibold">Findings by type</h2>
      {rows.length === 0 ? (
        <p className="text-xs text-muted">No open findings in the latest succeeded scans.</p>
      ) : (
        <ul className="flex flex-col gap-2.5">
          {rows.map((row) => (
            <li key={row.key} className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between gap-3">
                <span className="flex items-baseline gap-2 text-[13px]">
                  {row.label}
                  {row.key === 'license' ? (
                    <span className="text-xs text-faint">informational</span>
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
  return (
    <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
      <div className="flex flex-wrap items-baseline gap-2.5">
        <h2 className="text-[13px] font-semibold">Riskiest projects</h2>
        <span className="text-faint">Top 5 by open severity weight</span>
      </div>
      {assets.length === 0 ? (
        <p className="text-xs text-muted">No project has open findings right now.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="text-xs text-faint">
              <tr>
                <th className="pb-2 font-medium">Project</th>
                <th className="pb-2 text-right font-medium">Score</th>
                <th className="pb-2 pl-3 font-medium">Critical</th>
                <th className="pb-2 pl-2 font-medium">High</th>
                <th className="pb-2 pl-2 font-medium">Medium</th>
                <th className="pb-2 pl-2 font-medium">Low</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {assets.map((asset) => (
                <tr key={asset.asset_id}>
                  <td className="py-2 pr-3">
                    <Link
                      to="/security-reports"
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
  const title = `${label}: open critical and high findings over the last ${String(values.length)} succeeded ${values.length === 1 ? 'scan' : 'scans'}, oldest first: ${summary}`

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
  const cause =
    error instanceof ApiError
      ? `${error.message}${error.problem?.title ? ` (${error.problem.title})` : ''}`
      : error instanceof Error
        ? error.message
        : 'the request failed'

  return (
    <p role="alert" className="text-xs text-critical">
      {cause}{' '}
      <span className="text-muted">
        Reload the page; if it persists, check the terminal running bastion.
      </span>
    </p>
  )
}
