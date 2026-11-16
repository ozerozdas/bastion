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
import { t, useT } from '../lib/i18n'
import { formatDateTime, relativeTime, scanDuration } from '../lib/time'

/** statusView maps a scan status to its badge text and tone (§7.5). */
const statusView: Record<
  Scan['status'],
  { tone: 'neutral' | 'ok' | 'critical'; labelKey: string }
> = {
  queued: { tone: 'neutral', labelKey: 'scanStatus.queued' },
  running: { tone: 'neutral', labelKey: 'scanStatus.running' },
  succeeded: { tone: 'ok', labelKey: 'scanStatus.succeeded' },
  failed: { tone: 'critical', labelKey: 'scanStatus.failed' },
  canceled: { tone: 'neutral', labelKey: 'scanStatus.canceled' },
}

/** triggerLabels says who started the scan in the words used in the CLI. */
const triggerLabels: Record<Scan['trigger'], string> = {
  ui: 'UI',
  cli: 'CLI',
  api: 'API',
}

/** ScansPanel is the Repositories page's Scans tab: every scan of every asset. */
export function ScansPanel() {
  const t = useT()
  // The project filter lives in the URL (#54), so a filtered view can be
  // reloaded, bookmarked and shared.
  const assetId = useSearch({ from: '/repositories' }).asset
  const navigate = useNavigate()
  const setAssetId = (asset: number | undefined) => {
    void navigate({
      to: '/repositories',
      search: asset === undefined ? { tab: 'scans' } : { tab: 'scans', asset },
      replace: true,
    })
  }
  const assets = useQuery(assetsQuery)

  // A removed project's id must not stay in the URL with an empty list behind it.
  useEffect(() => {
    if (assetId === undefined || assets.data === undefined) return
    if (assets.data.some((asset) => asset.id === assetId)) return
    void navigate({ to: '/repositories', search: { tab: 'scans' }, replace: true })
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
      label: t('scans.column.project'),
      value: assetId === undefined ? '' : String(assetId),
      options: [
        { value: '', label: t('findings.filter.allProjects') },
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
          <h2 id="scans-heading" className="text-[0.8125rem] font-semibold">
            {t('scans.title')}
          </h2>
          <span className="text-faint">{t('scans.subtitle')}</span>
        </div>

        <FilterBar fields={filters} layout="inline" bordered={false} />

        {scans.isPending ? (
          <p className="text-muted">{t('scans.loading')}</p>
        ) : null}

        {scans.isError ? (
          <div className="flex flex-col gap-1">
            <h3 className="text-[0.8125rem] font-semibold">
              {t('scans.failed')}
            </h3>
            <ErrorNote error={scans.error} />
          </div>
        ) : null}

        {scans.isSuccess ? (
          scans.data.length === 0 ? (
            <p className="text-xs text-muted">
              {t('scans.emptyFiltered')}
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
  const t = useT()
  const names = useMemo(() => assetNames(assets), [assets])
  const columns: DataTableColumn<Scan>[] = [
    {
      id: 'project',
      header: t('scans.column.project'),
      cellClassName: 'max-w-[22ch] truncate py-2 pr-3',
      cell: (scan) => {
        const project =
          names.get(scan.asset_id) ??
          t('asset.fallback', { id: scan.asset_id })
        return (
          <Link
            to="/findings"
            search={{ asset: scan.asset_id }}
            className="hover:underline"
            title={t('scans.projectTitle', { project })}
          >
            {project}
          </Link>
        )
      },
    },
    {
      id: 'status',
      header: t('scans.column.status'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (scan) => {
        const status = statusView[scan.status]
        return <Badge tone={status.tone}>{t(status.labelKey)}</Badge>
      },
    },
    {
      id: 'findings',
      header: t('scans.column.findings'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (scan) => <SeverityCountBadges counts={scan.counts} />,
    },
    {
      id: 'trigger',
      header: t('scans.column.trigger'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 text-muted',
      cell: (scan) => triggerLabels[scan.trigger],
    },
    {
      id: 'started',
      header: t('scans.column.started'),
      headerClassName: 'pl-3 text-right',
      cellClassName:
        'py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums',
      cellTitle: (scan) =>
        scan.started_at ? formatDateTime(scan.started_at) : undefined,
      cell: (scan) => relativeTime(scan.started_at),
    },
    {
      id: 'duration',
      header: t('scans.column.duration'),
      headerClassName: 'pl-3 text-right',
      cellClassName:
        'py-2 pl-3 text-right whitespace-nowrap text-muted tabular-nums',
      cell: (scan) => scanDuration(scan),
    },
    {
      id: 'error',
      header: t('scans.column.error'),
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
      header: t('scans.column.actions'),
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
              title={t('scans.compareTitle', { id: scan.id })}
            >
              {t('scans.compare')}
            </Link>
            {/* ponytail: one export format, so a plain download; a menu when a second one lands. */}
            <a
              href={`/api/scans/${String(scan.id)}/sbom`}
              download
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
              title={t('scans.downloadSbomTitle', { id: scan.id })}
            >
              {t('scans.downloadSbom')}
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
  const t = useT()
  return (
    <EmptyState
      title={t('scans.empty.title')}
      body={t('scans.empty.body')}
    >
      <Link to="/repositories" className={buttonVariants({ variant: 'outline' })}>
        {t('scans.empty.action')}
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
        : t('common.requestFailed')

  return (
    <p role="alert" className="text-xs text-critical">
      {cause} <span className="text-muted">{t('common.reloadFix')}</span>
    </p>
  )
}
