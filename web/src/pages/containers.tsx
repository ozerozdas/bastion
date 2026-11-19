import { ScanScheduleSelect } from '../components/scan-schedule'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Fragment, useState } from 'react'

import {
  assetsQuery,
  useArchiveAsset,
  useClearAssetLink,
  useSetAssetLink,
  type Asset,
} from '../api/assets'
import { ApiError } from '../api/client'
import { connectionsQuery, type Connection } from '../api/connections'
import { dockerImagesQuery, useScanDockerImage, type DockerImage } from '../api/docker'
import {
  ecrDiscoverQuery,
  useScanEcrImage,
  type EcrRepository,
  type EcrTag,
} from '../api/ecr'
import { useScanEvents, type LiveScan } from '../api/events'
import { openFindingTotal } from '../api/reports'
import { useStartScans, type Scan } from '../api/scans'
import {
  DataTable,
  DataTableRow,
  MobileCellLabel,
  mobileCellProps,
  useTableSort,
  type DataTableColumn,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { SeverityCountBadges } from '../components/severity-counts'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { formatNumber, t, useT } from '../lib/i18n'
import { isLiveActive, liveDetail } from '../lib/live-scan'
import { relativeTime } from '../lib/time'
import type { ContainersTab } from '../lib/urls'

/** statusTone maps a scan status onto the badge colours Repositories uses. */
const statusTone: Record<Scan['status'], 'neutral' | 'ok' | 'critical'> = {
  queued: 'neutral',
  running: 'neutral',
  succeeded: 'ok',
  failed: 'critical',
  canceled: 'neutral',
}

/** ContainerRow is one local image and the asset that tracks it, if any. */
type ContainerRow = {
  image: DockerImage
  asset: Asset | undefined
}

/**
 * ContainersPage lists the local Docker daemon's images and every AWS
 * connection's ECR tags, one tab per source (#120). A tracked image shows its
 * last scan and findings, the way a project row does.
 */
export function ContainersPage() {
  const t = useT()
  const search = useSearch({ from: '/containers' })
  const navigate = useNavigate()
  const images = useQuery(dockerImagesQuery)
  const assets = useQuery(assetsQuery)
  const connections = useQuery(connectionsQuery)
  // One stream for the whole page, so a scan keeps updating whichever tab is
  // open, and after a tab switch the rows already have their live state.
  const live = useScanEvents()

  const list = assets.data ?? []
  const repos = list.filter((asset) => asset.kind === 'repo')
  const aws = (connections.data ?? []).filter(
    (connection) => connection.kind === 'aws',
  )
  // Images whose connection was removed before removal archived them: they
  // have no connection to be listed under, so the Orphaned tab is their only
  // place (issue #120).
  const orphaned = list.filter(
    (asset) =>
      asset.kind === 'image' &&
      asset.connection_id === undefined &&
      asset.ecr_registry?.includes('.dkr.ecr.') === true,
  )

  // Only a reachable daemon gets a tab; without one the hint stands alone.
  const tabs: TabItem<ContainersTab>[] = []
  if (images.data?.available === true) {
    tabs.push({ value: 'docker', label: t('containers.tabs.docker') })
  }
  for (const connection of aws) {
    tabs.push({
      value: `aws-${connection.id}`,
      label: t('containers.tabs.aws', { name: connection.name }),
    })
  }
  if (orphaned.length > 0) {
    tabs.push({ value: 'orphaned', label: t('containers.tabs.orphaned') })
  }
  // The first tab is the bare path, as on the other tabbed pages; a stale tab
  // (?tab=aws-9 once that connection is gone) falls back to it.
  const tab =
    tabs.find((item) => item.value === search.tab)?.value ?? tabs[0]?.value
  const connection = aws.find((item) => `aws-${item.id}` === tab)

  if (images.isPending || connections.isPending) {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">{t('containers.loading')}</p>
      </section>
    )
  }

  // A failed probe or connection list is shown above the tabs: the source it
  // would have added has no tab to carry the message.
  const errors = (
    <>
      {images.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={images.error} />
        </section>
      ) : null}
      {connections.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={connections.error} />
        </section>
      ) : null}
    </>
  )

  if (!tab) {
    return (
      <div className="flex flex-col gap-4">
        {errors}
        {images.isSuccess ? (
          <EmptyState
            title={t('containers.empty.docker.title')}
            body={t('containers.empty.docker.body')}
          />
        ) : null}
        <AWSHint />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      {errors}
      <Tabs
        label={t('containers.tabs.aria')}
        items={tabs}
        value={tab}
        onChange={(next) => {
          // The URL owns the tab, so a reload or a copied link lands on it.
          // replace: switching tabs is not a step the Back button should undo.
          void navigate({
            to: '/containers',
            search: next === tabs[0]?.value ? {} : { tab: next },
            replace: true,
          })
        }}
      >
        {tab === 'docker' ? <DockerPanel assets={list} live={live} /> : null}
        {tab === 'orphaned' ? <OrphanedImages assets={orphaned} /> : null}
        {connection ? (
          <EcrConnection
            connection={connection}
            assets={list}
            repos={repos}
            live={live}
          />
        ) : null}
      </Tabs>
      {/* Without an AWS connection the Docker tab is the only source, so the
          hint sits under it rather than behind a tab that does not exist. */}
      {aws.length === 0 ? <AWSHint /> : null}
    </div>
  )
}

/**
 * DockerPanel is the local daemon's images, one row each, with the scan and
 * link actions a tracked image offers.
 */
function DockerPanel({
  assets,
  live,
}: {
  assets: Asset[]
  live: Map<number, LiveScan>
}) {
  const t = useT()
  const images = useQuery(dockerImagesQuery)
  const scanImage = useScanDockerImage()
  const start = useStartScans()
  const archive = useArchiveAsset()
  const tableSort = useTableSort()
  const [confirmingID, setConfirmingID] = useState<number | null>(null)

  const rows: ContainerRow[] =
    images.data?.images.map((image) => ({
      image,
      asset: assets.find(
        (asset) => asset.kind === 'image' && asset.ref === image.reference,
      ),
    })) ?? []
  // The link control offers the tracked repositories.
  const repos = assets.filter((asset) => asset.kind === 'repo')

  function scanning(row: ContainerRow): boolean {
    if (row.asset) {
      return start.isPending && start.variables?.includes(row.asset.id) === true
    }
    return (
      scanImage.isPending && scanImage.variables?.reference === row.image.reference
    )
  }

  function scan(row: ContainerRow) {
    if (row.asset) {
      start.mutate([row.asset.id])
    } else {
      scanImage.mutate(row.image)
    }
  }

  const columns: DataTableColumn<ContainerRow>[] = [
    {
      id: 'image',
      header: t('containers.column.image'),
      sortable: true,
      mobile: 'primary',
      sortValue: (row) => row.image.reference,
      cell: (row) => (
        <div className="max-w-[32ch] max-xl:max-w-[22ch]">
          <span
            className="block truncate font-mono text-xs text-fg"
            title={row.image.reference}
          >
            {row.image.reference}
          </span>
          <span className="block truncate font-mono text-[0.6875rem] text-faint">
            {shortID(row.image.id)}
          </span>
        </div>
      ),
    },
    {
      id: 'size',
      header: t('containers.column.size'),
      // Size, age and schedule are the metadata that goes before the table
      // starts scrolling between md and xl.
      headerClassName: 'hidden pl-3 xl:table-cell',
      cellClassName: 'hidden pl-3 align-top whitespace-nowrap tabular-nums xl:table-cell',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'hidden',
      sortValue: (row) => row.image.size_bytes,
      cell: (row) => <span className="text-muted">{formatSize(row.image.size_bytes)}</span>,
    },
    {
      id: 'created',
      header: t('containers.column.created'),
      headerClassName: 'hidden pl-3 xl:table-cell',
      cellClassName: 'hidden pl-3 align-top whitespace-nowrap tabular-nums xl:table-cell',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'hidden',
      sortValue: (row) => row.image.created_at,
      cell: (row) => (
        <span className="text-muted">{relativeTime(row.image.created_at)}</span>
      ),
    },
    {
      id: 'last-scan',
      header: t('containers.column.lastScan'),
      headerClassName: 'status-cell-wide pl-3',
      cellClassName: 'status-cell-wide pl-3 align-top whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'status',
      sortValue: (row) => row.asset?.last_scan?.finished_at ?? '',
      cell: (row) => (
        <ScanCell
          asset={row.asset}
          live={row.asset ? live.get(row.asset.id) : undefined}
        />
      ),
    },
    {
      id: 'repository',
      header: t('containers.column.repository'),
      // The linked repository is the first column to go when the schedule needs
      // the room between md and xl; the card layout below md still shows it.
      headerClassName: 'hidden pl-3 xl:table-cell',
      cellClassName: 'hidden pl-3 align-top xl:table-cell',
      sortable: true,
      mobile: 'secondary',
      mobileLabel: t('containers.column.repository'),
      sortValue: (row) => row.asset?.display_name ?? '',
      cell: (row) => <LinkCell asset={row.asset} repos={repos} />,
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'counts',
      mobileLabel: t('containers.column.openFindings'),
      sortValue: (row) =>
        row.asset === undefined ? -1 : openFindingTotal(row.asset.open_counts),
      cell: (row) =>
        row.asset ? (
          <SeverityCountBadges counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'schedule',
      header: t('containers.column.schedule'),
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName: 'hidden pl-3 align-top md:table-cell',
      mobile: 'secondary',
      mobileLabel: t('containers.column.schedule'),
      cell: (row) =>
        row.asset ? (
          <ScanScheduleSelect asset={row.asset} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
      mobile: 'actions',
      cell: (row) => {
        const asset = row.asset
        const running = asset !== undefined && isRunning(asset, live.get(asset.id))
        return (
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => scan(row)}
              disabled={scanning(row) || running}
            >
              {scanning(row) ? t('containers.queueing') : t('containers.scan')}
            </Button>
            {asset ? (
              <>
                <Link
                  to="/findings"
                  search={{ asset: asset.id }}
                  className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                >
                  {t('containers.viewFindings')}
                </Link>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    scanImage.reset()
                    start.reset()
                    setConfirmingID(asset.id)
                  }}
                >
                  {t('containers.remove')}
                </Button>
              </>
            ) : null}
          </div>
        )
      },
    },
  ]

  return (
    <>
      {scanImage.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={scanImage.error} />
        </section>
      ) : null}
      {start.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={start.error} />
        </section>
      ) : null}

      {images.isSuccess && !images.data.available ? (
        <EmptyState
          title={t('containers.empty.docker.title')}
          body={t('containers.empty.docker.body')}
        />
      ) : null}

      {images.isSuccess &&
      images.data.available &&
      images.data.images.length === 0 ? (
        <EmptyState
          title={t('containers.empty.tagged.title')}
          body={t('containers.empty.tagged.body')}
        />
      ) : null}

      {images.isSuccess && images.data.available && rows.length > 0 ? (
        <section
          aria-label={t('containers.section.aria')}
          className="rounded-card border border-border-subtle bg-surface p-4"
        >
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(row) => `${row.image.reference}-${row.image.id}`}
            clientSort
            sort={tableSort.sort}
            onSortChange={tableSort.onSortChange}
            mobileCards
            renderRow={(row) => {
              const asset = row.asset
              return (
                <Fragment>
                  <DataTableRow cardMode>
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        className={column.cellClassName}
                        title={column.cellTitle?.(row)}
                        {...mobileCellProps(column)}
                      >
                        <MobileCellLabel label={column.mobileLabel} />
                        {column.cell?.(row)}
                      </td>
                    ))}
                  </DataTableRow>
                  {asset && confirmingID === asset.id ? (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ConfirmRemove
                          name={asset.display_name}
                          pending={archive.isPending}
                          onRemove={() =>
                            archive.mutate(asset.id, {
                              onSuccess: () => setConfirmingID(null),
                            })
                          }
                          onCancel={() => {
                            archive.reset()
                            setConfirmingID(null)
                          }}
                        />
                      </td>
                    </tr>
                  ) : null}
                  {asset && archive.isError && archive.variables === asset.id ? (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ErrorNote error={archive.error} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              )
            }}
          />
        </section>
      ) : null}
    </>
  )
}

/**
 * AWSHint is the way to ECR without an AWS connection: a link to the
 * Connections page's registry tab (#107).
 */
function AWSHint() {
  const t = useT()
  return (
    <section className="rounded-card border border-border-subtle bg-surface p-4">
      <p className="text-sm text-muted">
        <span>{t('containers.awsHint.before')}</span>{' '}
        <Link
          to="/connections"
          search={{ tab: 'registry' }}
          className="underline underline-offset-2 hover:text-fg"
        >
          {t('containers.awsHint.link')}
        </Link>{' '}
        {t('containers.awsHint.after')}
      </p>
    </section>
  )
}

/**
 * OrphanedImages lists ECR images whose AWS connection was removed. They no
 * longer appear under any connection, so this is where they can be archived.
 */
function OrphanedImages({ assets }: { assets: Asset[] }) {
  const t = useT()
  const archive = useArchiveAsset()
  const tableSort = useTableSort()

  const columns: DataTableColumn<Asset>[] = [
    {
      id: 'image',
      header: t('containers.column.image'),
      sortable: true,
      mobile: 'primary',
      sortValue: (asset) => asset.display_name,
      cell: (asset) => (
        <div className="max-w-[40ch]">
          <span
            className="block truncate font-mono text-xs text-fg"
            title={asset.ref}
          >
            {asset.display_name}
          </span>
          <span className="block truncate font-mono text-[0.6875rem] text-faint">
            {asset.ref}
          </span>
        </div>
      ),
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      sortable: true,
      defaultSortDirection: 'desc',
      sortValue: (asset) => openFindingTotal(asset.open_counts),
      cell: (asset) => <SeverityCountBadges counts={asset.open_counts} />,
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
      mobile: 'actions',
      cell: (asset) => {
        const archiving = archive.isPending && archive.variables === asset.id
        return (
          <div className="flex items-center justify-end">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => archive.mutate(asset.id)}
              disabled={archiving}
            >
              {archiving ? t('containers.archiving') : t('containers.archive')}
            </Button>
          </div>
        )
      },
    },
  ]

  return (
    <section
      aria-label={t('containers.orphaned.aria')}
      className="space-y-2"
    >
      <p className="text-xs text-muted">{t('containers.orphaned.body')}</p>
      {archive.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={archive.error} />
        </section>
      ) : null}
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <DataTable
          rows={assets}
          columns={columns}
          rowKey={(asset) => String(asset.id)}
          clientSort
          sort={tableSort.sort}
          onSortChange={tableSort.onSortChange}
          mobileCards
        />
      </section>
    </section>
  )
}

/** EcrRow is one ECR tag and the asset that tracks its digest, if any. */
type EcrRow = {
  repository: EcrRepository
  tag: EcrTag
  asset: Asset | undefined
}

/** EcrConnection lists one AWS connection's ECR repositories and tags. */
function EcrConnection({
  connection,
  assets,
  repos,
  live,
}: {
  connection: Connection
  assets: Asset[]
  repos: Asset[]
  live: Map<number, LiveScan>
}) {
  const t = useT()
  const discover = useQuery(ecrDiscoverQuery(connection.id))
  const scan = useScanEcrImage(connection.id)
  const archive = useArchiveAsset()
  const tableSort = useTableSort()
  const [confirmingID, setConfirmingID] = useState<number | null>(null)

  const rows: EcrRow[] = (discover.data ?? []).flatMap((repository) =>
    repository.tags.map((tag) => ({
      repository,
      tag,
      asset: assets.find(
        (asset) => asset.kind === 'image' && asset.ref === tag.ref,
      ),
    })),
  )

  function scanning(row: EcrRow): boolean {
    return scan.isPending && scan.variables?.ref === row.tag.ref
  }

  const columns: DataTableColumn<EcrRow>[] = [
    {
      id: 'image',
      header: t('containers.column.image'),
      sortable: true,
      sortValue: (row) => `${row.repository.name}:${row.tag.tags[0] ?? ''}`,
      cell: (row) => {
        const primary = row.tag.tags[0] ?? ''
        return (
          <div className="max-w-[40ch]">
            <span
              className="block truncate font-mono text-xs text-fg"
              title={`${row.repository.uri}:${primary}`}
            >
              {row.repository.name}:{primary}
            </span>
            <span className="block truncate font-mono text-[0.6875rem] text-faint">
              {shortID(row.tag.digest)}
              {row.tag.tags.length > 1
                ? ` · ${row.tag.tags.slice(1).join(' · ')}`
                : ''}
            </span>
          </div>
        )
      },
    },
    {
      id: 'pushed',
      header: t('containers.column.pushed'),
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap tabular-nums',
      sortable: true,
      defaultSortDirection: 'desc',
      sortValue: (row) => row.tag.pushed_at,
      cell: (row) => (
        <span className="text-muted">{relativeTime(row.tag.pushed_at)}</span>
      ),
    },
    {
      id: 'last-scan',
      header: t('containers.column.lastScan'),
      headerClassName: 'status-cell-wide pl-3',
      cellClassName: 'status-cell-wide pl-3 align-top whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'status',
      sortValue: (row) => row.asset?.last_scan?.finished_at ?? '',
      cell: (row) => (
        <ScanCell
          asset={row.asset}
          live={row.asset ? live.get(row.asset.id) : undefined}
        />
      ),
    },
    {
      id: 'repository',
      header: t('containers.column.repository'),
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      sortable: true,
      mobile: 'secondary',
      mobileLabel: t('containers.column.repository'),
      sortValue: (row) => row.asset?.display_name ?? '',
      cell: (row) => <LinkCell asset={row.asset} repos={repos} />,
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'counts',
      mobileLabel: t('containers.column.openFindings'),
      sortValue: (row) =>
        row.asset === undefined ? -1 : openFindingTotal(row.asset.open_counts),
      cell: (row) =>
        row.asset ? (
          <SeverityCountBadges counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'schedule',
      header: t('containers.column.schedule'),
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName: 'hidden pl-3 align-top md:table-cell',
      mobile: 'secondary',
      mobileLabel: t('containers.column.schedule'),
      cell: (row) =>
        row.asset ? (
          <ScanScheduleSelect asset={row.asset} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
      mobile: 'actions',
      cell: (row) => {
        const asset = row.asset
        const running = asset !== undefined && isRunning(asset, live.get(asset.id))
        return (
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => scan.mutate(row.tag)}
              disabled={scanning(row) || running}
            >
              {scanning(row)
                ? t('containers.queueing')
                : asset
                  ? t('containers.scan')
                  : t('containers.addAndScan')}
            </Button>
            {asset ? (
              <>
                <Link
                  to="/findings"
                  search={{ asset: asset.id }}
                  className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                >
                  {t('containers.viewFindings')}
                </Link>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    scan.reset()
                    setConfirmingID(asset.id)
                  }}
                >
                  {t('containers.remove')}
                </Button>
              </>
            ) : null}
          </div>
        )
      },
    },
  ]

  return (
    <section className="space-y-2">
      <h2 className="text-[0.8125rem] font-semibold">
        {connection.name}
        {connection.region ? (
          <span className="ml-2 font-mono text-[0.6875rem] font-normal text-faint">
            {connection.region}
          </span>
        ) : null}
      </h2>
      {discover.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={discover.error} />
        </section>
      ) : null}
      {scan.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={scan.error} />
        </section>
      ) : null}
      {discover.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('containers.listing')}</p>
        </section>
      ) : null}
      {discover.isSuccess && rows.length === 0 ? (
        <EmptyState
          title={t('containers.ecrEmpty.title')}
          body={t('containers.ecrEmpty.body')}
        />
      ) : null}
      {rows.length > 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(row) => row.tag.ref}
            clientSort
            sort={tableSort.sort}
            onSortChange={tableSort.onSortChange}
            mobileCards
            renderRow={(row) => {
              const asset = row.asset
              return (
                <Fragment>
                  <DataTableRow cardMode>
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        className={column.cellClassName}
                        title={column.cellTitle?.(row)}
                        {...mobileCellProps(column)}
                      >
                        <MobileCellLabel label={column.mobileLabel} />
                        {column.cell?.(row)}
                      </td>
                    ))}
                  </DataTableRow>
                  {asset && confirmingID === asset.id ? (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ConfirmRemove
                          name={asset.display_name}
                          pending={archive.isPending}
                          onRemove={() =>
                            archive.mutate(asset.id, {
                              onSuccess: () => setConfirmingID(null),
                            })
                          }
                          onCancel={() => {
                            archive.reset()
                            setConfirmingID(null)
                          }}
                        />
                      </td>
                    </tr>
                  ) : null}
                  {asset && archive.isError && archive.variables === asset.id ? (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ErrorNote error={archive.error} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              )
            }}
          />
        </section>
      ) : null}
    </section>
  )
}

/**
 * LinkCell shows the repository an image was built from and the control that
 * sets or clears the link. The badge names the source: `manual` is a user's
 * choice and is never overwritten by a later scan, `oci` came from the image's
 * own labels.
 */
function LinkCell({ asset, repos }: { asset: Asset | undefined; repos: Asset[] }) {
  const t = useT()
  const setLink = useSetAssetLink()
  const clearLink = useClearAssetLink()
  const [choice, setChoice] = useState('')

  if (!asset) {
    return <span className="text-faint">—</span>
  }

  const error = setLink.error ?? clearLink.error

  return (
    <div className="flex max-w-[30ch] flex-col gap-1">
      {asset.linked_repo ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className="max-w-[18ch] truncate font-mono text-xs text-fg"
            title={asset.linked_repo.ref}
          >
            {asset.linked_repo.ref}
          </span>
          <Badge tone={asset.linked_repo.source === 'manual' ? 'neutral' : 'ok'}>
            {asset.linked_repo.source}
          </Badge>
          {asset.linked_repo.revision ? (
            <span
              className="font-mono text-[0.6875rem] text-faint"
              title={t('containers.link.revision', {
                revision: asset.linked_repo.revision,
              })}
            >
              {asset.linked_repo.revision.slice(0, 7)}
            </span>
          ) : null}
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => clearLink.mutate(asset.id)}
            disabled={clearLink.isPending}
          >
            {clearLink.isPending
              ? t('containers.link.unlinking')
              : t('containers.link.unlink')}
          </Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-1.5">
          <select
            aria-label={t('containers.link.aria', {
              name: asset.display_name,
            })}
            value={choice}
            onChange={(event) => setChoice(event.target.value)}
            className="h-7 max-w-[18ch] rounded-md border border-border-strong bg-surface px-1.5 text-[0.75rem] text-fg"
          >
            <option value="">{t('containers.link.to')}</option>
            {repos.map((repo) => (
              <option key={repo.id} value={repo.id}>
                {repo.ref}
              </option>
            ))}
          </select>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() =>
              setLink.mutate(
                { imageId: asset.id, repoId: Number(choice) },
                { onSuccess: () => setChoice('') },
              )
            }
            disabled={choice === '' || setLink.isPending}
          >
            {setLink.isPending
              ? t('containers.link.linking')
              : t('containers.link.link')}
          </Button>
        </div>
      )}
      {error ? (
        <span role="alert" className="text-[0.6875rem] text-critical">
          {error instanceof ApiError
            ? error.message
            : t('containers.link.failed')}
        </span>
      ) : null}
    </div>
  )
}

/**
 * ConfirmRemove is the inline confirmation a tracked image row shows before it
 * is archived. It matches the Repositories table's remove confirmation.
 */
function ConfirmRemove({
  name,
  pending,
  onRemove,
  onCancel,
}: {
  name: string
  pending: boolean
  onRemove: () => void
  onCancel: () => void
}) {
  const t = useT()
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
      <span>{t('containers.confirmRemove', { name })}</span>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="text-critical"
        onClick={onRemove}
        disabled={pending}
      >
        {pending ? t('containers.removing') : t('containers.remove')}
      </Button>
      <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
        {t('containers.cancel')}
      </Button>
    </div>
  )
}

/** isRunning reports whether a tracked image's scan is still in flight. */
function isRunning(asset: Asset, live: LiveScan | undefined): boolean {
  if (isLiveActive(live)) {
    return true
  }
  return (
    asset.last_scan?.status === 'queued' || asset.last_scan?.status === 'running'
  )
}

/** ScanCell shows the tracked asset's last scan, or that it is not tracked. */
function ScanCell({
  asset,
  live,
}: {
  asset: Asset | undefined
  live: LiveScan | undefined
}) {
  const t = useT()
  if (!asset) {
    return <Badge>{t('scanStatus.notTracked')}</Badge>
  }
  const lastScan = asset.last_scan
  // A live event wins over the list row until the finished event refetches it.
  const active = isLiveActive(live)
  const status = active && live ? live.status : lastScan?.status
  if (!status) {
    return <Badge>{t('scanStatus.neverScanned')}</Badge>
  }
  return (
    <span className="inline-flex items-center gap-2">
      <Badge tone={statusTone[status]}>{t(`scanStatus.${status}`)}</Badge>
      <span className="text-xs text-faint tabular-nums">
        {active
          ? t('scanStatus.inProgress')
          : lastScan?.finished_at
            ? relativeTime(lastScan.finished_at)
            : ''}
      </span>
      {active && live ? (
        <span className="text-xs text-muted">{liveDetail(live)}</span>
      ) : null}
    </span>
  )
}

/** shortID trims the algorithm prefix and keeps the id readable in a row. */
function shortID(id: string): string {
  const value = id.startsWith('sha256:') ? id.slice('sha256:'.length) : id
  return value.slice(0, 12)
}

/** formatSize renders an image size in MiB or GiB. */
function formatSize(bytes: number): string {
  const mib = bytes / (1024 * 1024)
  if (mib >= 1024) {
    return `${formatNumber(mib / 1024, {
      minimumFractionDigits: 1,
      maximumFractionDigits: 1,
    })} GiB`
  }
  return `${formatNumber(Math.max(1, Math.round(mib)))} MiB`
}

/** ErrorNote shows a failed request with a human cause. */
function ErrorNote({ error }: { error: unknown }) {
  const cause =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : t('common.requestFailed')
  return (
    <p role="alert" className="text-xs text-critical">
      {cause} <span className="text-muted">{t('common.reloadFix')}</span>
    </p>
  )
}
