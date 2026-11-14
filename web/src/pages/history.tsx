import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useMemo } from 'react'

import { assetsQuery, type Asset } from '../api/assets'
import { ApiError } from '../api/client'
import { scansQuery, type Scan } from '../api/scans'
import { DataTable, type DataTableColumn } from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { FilterBar } from '../components/filter-bar'
import { SeverityCountBadges } from '../components/severity-counts'
import { Badge } from '../components/ui/badge'
import { buttonVariants } from '../components/ui/button'
import { formatDateTime, relativeTime, scanDuration } from '../lib/time'

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

/** ScansPanel is the Projects page's Scans tab: every scan of every project. */
export function ScansPanel() {
  // The project filter lives in the URL (#54), so a filtered view can be
  // reloaded, bookmarked and shared.
  const assetId = useSearch({ from: '/projects' }).asset
  const navigate = useNavigate()
  const setAssetId = (asset: number | undefined) => {
    void navigate({
      to: '/projects',
      search: asset === undefined ? { tab: 'scans' } : { tab: 'scans', asset },
      replace: true,
    })
  }
  const assets = useQuery(assetsQuery)

  // A removed project's id must not stay in the URL with an empty list behind it.
  useEffect(() => {
    if (assetId === undefined || assets.data === undefined) return
    if (assets.data.some((asset) => asset.id === assetId)) return
    void navigate({ to: '/projects', search: { tab: 'scans' }, replace: true })
  }, [assetId, assets.data, navigate])

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

  const filters = [
    {
      id: 'scan-asset-filter',
      label: 'Project',
      value: assetId === undefined ? '' : String(assetId),
      options: [
        { value: '', label: 'All projects' },
        ...(assets.data ?? []).map((asset) => ({
          value: String(asset.id),
          label: asset.display_name,
        })),
      ],
      onChange: (value: string) => {
        setAssetId(value === '' ? undefined : Number(value))
      },
    },
  ]

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

        <FilterBar fields={filters} layout="inline" bordered={false} />

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
  const columns: DataTableColumn<Scan>[] = [
    {
      id: 'project',
      header: 'Project',
      cellClassName: 'max-w-[22ch] truncate py-2 pr-3',
      cell: (scan) => {
        const project =
          names.get(scan.asset_id) ?? `Asset ${String(scan.asset_id)}`
        return (
          <Link
            to="/findings"
            search={{ asset: scan.asset_id }}
            className="hover:underline"
            title={`${project}: open its findings`}
          >
            {project}
          </Link>
        )
      },
    },
    {
      id: 'status',
      header: 'Status',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (scan) => {
        const status = statusView[scan.status]
        return <Badge tone={status.tone}>{status.label}</Badge>
      },
    },
    {
      id: 'findings',
      header: 'Findings',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (scan) => <SeverityCountBadges counts={scan.counts} />,
    },
    {
      id: 'trigger',
      header: 'Trigger',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 text-muted',
      cell: (scan) => triggerLabels[scan.trigger],
    },
    {
      id: 'started',
      header: 'Started',
      headerClassName: 'pl-3 text-right',
      cellClassName:
        'py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums',
      cellTitle: (scan) =>
        scan.started_at ? formatDateTime(scan.started_at) : undefined,
      cell: (scan) => relativeTime(scan.started_at),
    },
    {
      id: 'duration',
      header: 'Duration',
      headerClassName: 'pl-3 text-right',
      cellClassName:
        'py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums',
      cell: (scan) => scanDuration(scan),
    },
    {
      id: 'error',
      header: 'Error',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (scan) =>
        scan.error ? (
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
        ),
    },
    {
      id: 'actions',
      header: 'Actions',
      headerClassName: 'pl-3 text-right',
      cellClassName: 'py-2 pl-3 whitespace-nowrap text-right',
      cell: (scan) =>
        // Only a succeeded scan has a complete finding set and inventory.
        scan.status === 'succeeded' ? (
          <div className="inline-flex items-center gap-1.5">
            <Link
              to="/scans/$scanId/diff"
              params={{ scanId: String(scan.id) }}
              className={buttonVariants({ variant: 'outline', size: 'sm' })}
              title={`Compare scan #${String(scan.id)} with the previous one`}
            >
              Compare
            </Link>
            {/* ponytail: one export format, so a plain download; a menu when a second one lands. */}
            <a
              href={`/api/scans/${String(scan.id)}/sbom`}
              download
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
              title={`Download the CycloneDX SBOM of scan #${String(scan.id)}`}
            >
              Download SBOM
            </a>
          </div>
        ) : (
          <span aria-hidden="true" className="text-faint">
            —
          </span>
        ),
    },
  ]

  return (
    <DataTable
      rows={scans}
      columns={columns}
      rowKey={(scan) => String(scan.id)}
    />
  )
}

/** ScansEmpty explains how to get the first scan. */
function ScansEmpty() {
  return (
    <EmptyState
      title="No scans yet — add a project and press Scan"
      body="Every scan is listed here with its status and duration. Once two scans have finished, Compare shows what is new, fixed or still open between them."
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
