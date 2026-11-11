import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'

import { assetsQuery, type Asset } from '../api/assets'
import { ApiError } from '../api/client'
import { scansQuery, type Scan } from '../api/scans'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { buttonVariants } from '../components/ui/button'

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

/** statusView maps a scan status to its badge text and tone (§7.5). */
const statusView: Record<
  Scan['status'],
  { tone: 'neutral' | 'ok' | 'critical'; label: string }
> = {
  queued: { tone: 'neutral', label: 'queued' },
  running: { tone: 'neutral', label: 'running' },
  succeeded: { tone: 'ok', label: 'succeeded' },
  failed: { tone: 'critical', label: 'failed' },
  canceled: { tone: 'neutral', label: 'canceled' },
}

/** triggerLabels says who started the scan in the words used in the CLI. */
const triggerLabels: Record<Scan['trigger'], string> = {
  ui: 'UI',
  cli: 'CLI',
  api: 'API',
}

const selectClass =
  'h-8 rounded-md border border-border-strong bg-surface px-2 text-[13px] text-fg'

export function HistoryPage() {
  const [assetId, setAssetId] = useState<number | undefined>(undefined)
  const assets = useQuery(assetsQuery)

  // Poll while any scan in the list is still queued or running, so the status
  // and duration fill in without a manual reload.
  const scans = useQuery({
    ...scansQuery(assetId),
    refetchInterval: (query) =>
      query.state.data?.some(
        (scan) => scan.status === 'queued' || scan.status === 'running',
      )
        ? 5000
        : false,
  })

  // Nothing scanned and no filter to explain: the empty state is the page.
  if (scans.isSuccess && scans.data.length === 0 && assetId === undefined) {
    return <ScansEmpty />
  }

  return (
    <>
      <section
        aria-labelledby="scans-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 id="scans-heading" className="text-[13px] font-semibold">
            Scans
          </h2>
          <span className="text-faint">
            Newest first; every scan keeps its own findings
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="scan-asset-filter" className="text-xs text-muted">
            Project
          </label>
          <select
            id="scan-asset-filter"
            className={selectClass}
            value={assetId === undefined ? '' : String(assetId)}
            onChange={(event) => {
              const value = event.target.value
              setAssetId(value === '' ? undefined : Number(value))
            }}
          >
            <option value="">All projects</option>
            {(assets.data ?? []).map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.display_name}
              </option>
            ))}
          </select>
          <span className="text-xs text-faint">
            Comparing two scans arrives in v0.2.
          </span>
        </div>

        {scans.isPending ? <p className="text-muted">Loading scans…</p> : null}

        {scans.isError ? (
          <div className="flex flex-col gap-1">
            <h3 className="text-[13px] font-semibold">Scans failed to load</h3>
            <ErrorNote error={scans.error} />
          </div>
        ) : null}

        {scans.isSuccess ? (
          scans.data.length === 0 ? (
            <p className="text-xs text-muted">
              No scans for this project yet. Pick another project, or scan this
              one from Projects.
            </p>
          ) : (
            <ScanTable scans={scans.data} assets={assets.data ?? []} />
          )
        ) : null}
      </section>
    </>
  )
}

/** ScanTable lists scans with the one link that matters: open the report. */
function ScanTable({ scans, assets }: { scans: Scan[]; assets: Asset[] }) {
  const names = useMemo(() => assetNames(assets), [assets])

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead className="text-xs text-faint">
          <tr>
            <th className="pb-2 font-medium">Project</th>
            <th className="pb-2 pl-3 font-medium">Status</th>
            <th className="pb-2 pl-3 font-medium">Trigger</th>
            <th className="pb-2 pl-3 text-right font-medium">Started</th>
            <th className="pb-2 pl-3 text-right font-medium">Duration</th>
            <th className="pb-2 pl-3 font-medium">Error</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle">
          {scans.map((scan) => {
            const status = statusView[scan.status]
            const project =
              names.get(scan.asset_id) ?? `Asset ${String(scan.asset_id)}`
            return (
              <tr key={scan.id}>
                <td className="max-w-[22ch] truncate py-2 pr-3">
                  <Link
                    to="/security-reports"
                    search={{ asset: scan.asset_id }}
                    className="hover:underline"
                    title={`${project}: open the security report`}
                  >
                    {project}
                  </Link>
                </td>
                <td className="py-2 pl-3">
                  <Badge tone={status.tone}>{status.label}</Badge>
                </td>
                <td className="py-2 pl-3 text-muted">
                  {triggerLabels[scan.trigger]}
                </td>
                <td
                  className="py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums"
                  title={
                    scan.started_at
                      ? dateTimeFormat.format(new Date(scan.started_at))
                      : undefined
                  }
                >
                  {relativeTime(scan.started_at)}
                </td>
                <td className="py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums">
                  {duration(scan)}
                </td>
                <td className="py-2 pl-3">
                  {scan.error ? (
                    <span
                      className="block max-w-[32ch] truncate text-critical"
                      title={scan.error}
                    >
                      {scan.error}
                    </span>
                  ) : (
                    <span aria-hidden="true" className="text-faint">
                      —
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** ScansEmpty explains how to get the first scan. */
function ScansEmpty() {
  return (
    <EmptyState
      title="No scans yet — add a project and press Scan"
      body="Every scan is listed here with its status and duration. Once two scans have finished you can compare them to see what is new, fixed or still open. Comparing two scans arrives in v0.2."
    >
      <Link to="/projects" className={buttonVariants({ variant: 'outline' })}>
        Go to projects
      </Link>
    </EmptyState>
  )
}

/** assetNames maps asset ids to the names the rest of the UI shows. */
function assetNames(assets: Asset[]): Map<number, string> {
  const names = new Map<number, string>()
  for (const asset of assets) {
    names.set(asset.id, asset.display_name)
  }
  return names
}

/** duration is finished minus started, phrased in one short unit chain. */
function duration(scan: Scan): string {
  if (!scan.started_at) {
    return scan.status === 'queued' ? 'waiting' : '—'
  }
  const started = new Date(scan.started_at).getTime()
  const finished = scan.finished_at ? new Date(scan.finished_at).getTime() : NaN
  if (Number.isNaN(started) || Number.isNaN(finished)) {
    return scan.status === 'running' ? 'running' : '—'
  }
  const seconds = Math.max(0, Math.round((finished - started) / 1000))
  if (seconds < 60) {
    return `${String(seconds)}s`
  }
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) {
    return `${String(minutes)}m ${String(seconds % 60)}s`
  }
  const hours = Math.floor(minutes / 60)
  return `${String(hours)}h ${String(minutes % 60)}m`
}

/** relativeTime says when a scan started, falling back to the full date. */
function relativeTime(timestamp: string | undefined): string {
  if (!timestamp) {
    return 'not started'
  }
  const then = new Date(timestamp).getTime()
  if (Number.isNaN(then)) {
    return 'unknown'
  }
  const seconds = (then - Date.now()) / 1000
  const magnitude = Math.abs(seconds)
  if (magnitude < 45) {
    return 'just now'
  }
  if (magnitude < 3600) {
    return relativeFormat.format(Math.round(seconds / 60), 'minute')
  }
  if (magnitude < 86_400) {
    return relativeFormat.format(Math.round(seconds / 3600), 'hour')
  }
  if (magnitude < 2_592_000) {
    return relativeFormat.format(Math.round(seconds / 86_400), 'day')
  }
  return dateTimeFormat.format(new Date(then))
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
