import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Fragment, useState } from 'react'

import {
  assetsQuery,
  useArchiveAsset,
  useClearAssetLink,
  useSetAssetLink,
  useSetAssetSchedule,
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
import {
  BandHeader,
  BandMeta,
  BandSummary,
  SeverityMix,
  type BandMetaItem,
} from '../components/page-band'
import { OpenSeverityCounts, SeverityCountBadges } from '../components/severity-counts'
import {
  ActionMenu,
  type ActionMenuItem,
  type ActionMenuRadio,
} from '../components/ui/action-menu'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { assetStats, type AssetStats } from '../lib/asset-stats'
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
  const imageAssets = list.filter((asset) => asset.kind === 'image')
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

  // The active ECR tab's discovery is the very query EcrConnection runs, so
  // the hero counts its tags without a second request. A missing tab disables
  // the query through the id guard in ecrDiscoverQuery.
  const ecr = useQuery(ecrDiscoverQuery(connection?.id ?? 0))

  // Each tab summarises its own source. The findings, schedule and last scan
  // come from the tracked image assets that belong to that source; the first
  // count is the source's own images, which are not tracked assets yet.
  // ponytail: a failed ECR discovery leaves that count at 0 while the tracked
  // assets still carry their own numbers.
  const heroStats = ((): BandMetaItem[] => {
    if (tab === 'orphaned') {
      return containerHeroStats(
        t('containers.hero.orphaned'),
        orphaned.length,
        assetStats(orphaned),
        { scheduled: false },
      )
    }
    if (connection !== undefined) {
      const tracked = imageAssets.filter(
        (asset) => asset.connection_id === connection.id,
      )
      const ecrImages = (ecr.data ?? []).reduce(
        (total, repository) => total + repository.tags.length,
        0,
      )
      return containerHeroStats(
        t('containers.hero.ecr'),
        ecrImages,
        assetStats(tracked),
      )
    }
    // Docker: only images the daemon still lists have a tracked counterpart.
    const refs = new Set((images.data?.images ?? []).map((image) => image.reference))
    return containerHeroStats(
      t('containers.hero.local'),
      images.data?.images.length ?? 0,
      assetStats(imageAssets.filter((asset) => refs.has(asset.ref))),
    )
  })()

  function changeTab(next: ContainersTab) {
    // The URL owns the tab, so a reload or a copied link lands on it.
    // replace: switching tabs is not a step the Back button should undo.
    void navigate({
      to: '/containers',
      search: next === tabs[0]?.value ? {} : { tab: next },
      replace: true,
    })
  }

  if (images.isPending || connections.isPending) {
    return (
      <>
        <BandHeader>
          <BandSummary
            title={t('nav.containers')}
            subtitle={t('nav.containers.subtitle')}
          />
        </BandHeader>
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('containers.loading')}</p>
        </section>
      </>
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

  const subtitle =
    tab === 'orphaned'
      ? t('containers.subtitle.orphaned')
      : connection !== undefined
        ? t('containers.subtitle.ecr')
        : t('nav.containers.subtitle')
  const summary = (
    <BandSummary
      title={t('nav.containers')}
      subtitle={subtitle}
      meta={<BandMeta items={heroStats} />}
    />
  )

  return (
    <>
      {tab === undefined ? <BandHeader>{summary}</BandHeader> : null}
      <div className="flex flex-col gap-4">
        {errors}
        {tab === undefined ? (
          images.isSuccess ? (
            <EmptyState
              title={t('containers.empty.docker.title')}
              body={t('containers.empty.docker.body')}
            />
          ) : null
        ) : (
          <Tabs
            label={t('containers.tabs.aria')}
            items={tabs}
            value={tab}
            onChange={changeTab}
            band={{ summary }}
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
        )}
        {/* Without an AWS connection the Docker tab is the only source, so the
            hint sits under it rather than behind a tab that does not exist. */}
        {aws.length === 0 ? <AWSHint /> : null}
      </div>
    </>
  )
}

/**
 * containerHeroStats is the figures every container tab shares, with the tab's
 * own image count under a label that names the source.
 */
function containerHeroStats(
  imagesLabel: string,
  images: number,
  stats: AssetStats,
  options: { scheduled?: boolean } = {},
): BandMetaItem[] {
  return [
    { key: 'images', label: imagesLabel, value: images },
    ...(options.scheduled === false
      ? []
      : [
          {
            key: 'scheduled',
            label: t('containers.hero.scheduled'),
            value: stats.scheduled,
          },
        ]),
    {
      key: 'findings',
      label: t('containers.hero.openFindings'),
      value: (
        <>
          {openFindingTotal(stats.open)}
          <SeverityMix totals={stats.open} />
        </>
      ),
    },
    {
      key: 'last-scan',
      label: t('containers.hero.lastScan'),
      value:
        stats.lastScan === undefined
          ? t('containers.hero.none')
          : relativeTime(stats.lastScan),
    },
  ]
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
  const setLink = useSetAssetLink()
  const clearLink = useClearAssetLink()
  const schedule = useSetAssetSchedule()
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
      // One line per row: the full reference and the image id live in the
      // tooltip, so a long tag never grows the row.
      cell: (row) => (
        <span
          className="block max-w-[28ch] truncate font-mono text-xs text-fg"
          title={`${row.image.reference} · ${shortID(row.image.id)}`}
        >
          {row.image.reference}
        </span>
      ),
    },
    {
      id: 'size',
      header: t('containers.column.size'),
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName:
        'hidden py-2 pl-3 align-middle whitespace-nowrap tabular-nums md:table-cell',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'hidden',
      sortValue: (row) => row.image.size_bytes,
      cell: (row) => <span className="text-muted">{formatSize(row.image.size_bytes)}</span>,
    },
    {
      id: 'last-scan',
      header: t('containers.column.lastScan'),
      headerClassName: 'status-cell-wide pl-3',
      cellClassName: 'status-cell-wide py-2 pl-3 align-middle whitespace-nowrap',
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
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName: 'hidden py-2 pl-3 align-middle md:table-cell',
      sortable: true,
      mobile: 'secondary',
      mobileLabel: t('containers.column.repository'),
      sortValue: (row) => row.asset?.display_name ?? '',
      cell: (row) => <LinkedRepoCell asset={row.asset} />,
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 align-middle whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'counts',
      mobileLabel: t('containers.column.openFindings'),
      sortValue: (row) =>
        row.asset === undefined ? -1 : openFindingTotal(row.asset.open_counts),
      cell: (row) =>
        row.asset ? (
          <OpenSeverityCounts counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'py-2 pl-3 align-middle',
      mobile: 'actions',
      cell: (row) => {
        const asset = row.asset
        const running = asset !== undefined && isRunning(asset, live.get(asset.id))
        const items: ActionMenuItem[] =
          asset === undefined
            ? []
            : [
                {
                  key: 'findings',
                  label: t('containers.viewFindings'),
                  to: '/findings',
                  search: { asset: asset.id },
                },
                ...(asset.linked_repo === undefined
                  ? []
                  : [
                      {
                        key: 'unlink',
                        label: t('containers.link.unlink'),
                        disabled: clearLink.isPending,
                        onSelect: () => clearLink.mutate(asset.id),
                      },
                    ]),
                {
                  key: 'remove',
                  label: t('containers.remove'),
                  destructive: true,
                  onSelect: () => {
                    scanImage.reset()
                    start.reset()
                    setConfirmingID(asset.id)
                  },
                },
              ]
        const radios: ActionMenuRadio[] =
          asset === undefined
            ? []
            : [
                ...(asset.linked_repo === undefined && repos.length > 0
                  ? [
                      {
                        label: t('containers.link.aria', {
                          name: asset.display_name,
                        }),
                        title: t('containers.link.to'),
                        value: '',
                        options: repos.map((repo) => ({
                          value: String(repo.id),
                          label: repo.ref,
                        })),
                        disabled: setLink.isPending,
                        onChange: (value: string) =>
                          setLink.mutate({
                            imageId: asset.id,
                            repoId: Number(value),
                          }),
                      },
                    ]
                  : []),
                {
                  label: t('schedule.aria', { name: asset.display_name }),
                  title: t('containers.column.schedule'),
                  value: asset.scan_schedule,
                  options: [
                    { value: 'off', label: t('schedule.off') },
                    { value: 'daily', label: t('schedule.daily') },
                    { value: 'weekly', label: t('schedule.weekly') },
                  ],
                  disabled: schedule.isPending,
                  onChange: (value: string) =>
                    schedule.mutate({
                      id: asset.id,
                      schedule: value as Asset['scan_schedule'],
                    }),
                },
              ]
        return (
          <div className="flex items-center justify-end gap-1 whitespace-nowrap">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => scan(row)}
              disabled={scanning(row) || running}
            >
              {scanning(row) ? t('containers.queueing') : t('containers.scan')}
            </Button>
            {asset === undefined ? null : (
              <ActionMenu
                label={t('containers.actions.aria', { name: asset.display_name })}
                // ponytail: the shared "⋯" trigger, turned upright.
                className="rotate-90"
                items={items}
                radio={radios}
              />
            )}
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
              // The link and unlink controls live in the row's menu, so their
              // failure gets the same sub-row an inline control had.
              const linkError =
                asset === undefined
                  ? undefined
                  : setLink.isError && setLink.variables?.imageId === asset.id
                    ? setLink.error
                    : clearLink.isError && clearLink.variables === asset.id
                      ? clearLink.error
                      : undefined
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
                  {linkError === undefined ? null : (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ErrorNote error={linkError} />
                      </td>
                    </tr>
                  )}
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
      cellClassName: 'max-w-[44ch] py-2 pr-3 align-middle',
      sortValue: (asset) => asset.display_name,
      cell: (asset) => (
        <span
          className="block max-w-[44ch] truncate font-mono text-xs text-fg"
          title={asset.ref}
        >
          {asset.display_name}
        </span>
      ),
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 align-middle whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      sortValue: (asset) => openFindingTotal(asset.open_counts),
      cell: (asset) => <SeverityCountBadges counts={asset.open_counts} />,
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'py-2 pl-3 align-middle',
      mobile: 'actions',
      cell: (asset) => {
        const archiving = archive.isPending && archive.variables === asset.id
        return (
          <div className="flex items-center justify-end whitespace-nowrap">
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
  const setLink = useSetAssetLink()
  const clearLink = useClearAssetLink()
  const schedule = useSetAssetSchedule()
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
      mobile: 'primary',
      sortValue: (row) => `${row.repository.name}:${row.tag.tags[0] ?? ''}`,
      // One line: the digest and any extra tags sit in the tooltip.
      cell: (row) => {
        const primary = row.tag.tags[0] ?? ''
        const extra =
          row.tag.tags.length > 1 ? ` · ${row.tag.tags.slice(1).join(' · ')}` : ''
        return (
          <span
            className="block max-w-[32ch] truncate font-mono text-xs text-fg"
            title={`${row.repository.uri}:${primary} · ${shortID(row.tag.digest)}${extra}`}
          >
            {row.repository.name}:{primary}
          </span>
        )
      },
    },
    {
      id: 'pushed',
      header: t('containers.column.pushed'),
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName:
        'hidden py-2 pl-3 align-middle whitespace-nowrap tabular-nums md:table-cell',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'hidden',
      sortValue: (row) => row.tag.pushed_at,
      cell: (row) => (
        <span className="text-muted">{relativeTime(row.tag.pushed_at)}</span>
      ),
    },
    {
      id: 'last-scan',
      header: t('containers.column.lastScan'),
      headerClassName: 'status-cell-wide pl-3',
      cellClassName: 'status-cell-wide py-2 pl-3 align-middle whitespace-nowrap',
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
      headerClassName: 'hidden pl-3 md:table-cell',
      cellClassName: 'hidden py-2 pl-3 align-middle md:table-cell',
      sortable: true,
      mobile: 'secondary',
      mobileLabel: t('containers.column.repository'),
      sortValue: (row) => row.asset?.display_name ?? '',
      cell: (row) => <LinkedRepoCell asset={row.asset} />,
    },
    {
      id: 'open-findings',
      header: t('containers.column.openFindings'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 align-middle whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      mobile: 'counts',
      mobileLabel: t('containers.column.openFindings'),
      sortValue: (row) =>
        row.asset === undefined ? -1 : openFindingTotal(row.asset.open_counts),
      cell: (row) =>
        row.asset ? (
          <OpenSeverityCounts counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: t('containers.column.actions'),
      headerClassName: 'pl-3 text-right',
      cellClassName: 'py-2 pl-3 align-middle',
      mobile: 'actions',
      cell: (row) => {
        const asset = row.asset
        const running = asset !== undefined && isRunning(asset, live.get(asset.id))
        const items: ActionMenuItem[] =
          asset === undefined
            ? []
            : [
                {
                  key: 'findings',
                  label: t('containers.viewFindings'),
                  to: '/findings',
                  search: { asset: asset.id },
                },
                ...(asset.linked_repo === undefined
                  ? []
                  : [
                      {
                        key: 'unlink',
                        label: t('containers.link.unlink'),
                        disabled: clearLink.isPending,
                        onSelect: () => clearLink.mutate(asset.id),
                      },
                    ]),
                {
                  key: 'remove',
                  label: t('containers.remove'),
                  destructive: true,
                  onSelect: () => {
                    scan.reset()
                    setConfirmingID(asset.id)
                  },
                },
              ]
        const radios: ActionMenuRadio[] =
          asset === undefined
            ? []
            : [
                ...(asset.linked_repo === undefined && repos.length > 0
                  ? [
                      {
                        label: t('containers.link.aria', {
                          name: asset.display_name,
                        }),
                        title: t('containers.link.to'),
                        value: '',
                        options: repos.map((repo) => ({
                          value: String(repo.id),
                          label: repo.ref,
                        })),
                        disabled: setLink.isPending,
                        onChange: (value: string) =>
                          setLink.mutate({
                            imageId: asset.id,
                            repoId: Number(value),
                          }),
                      },
                    ]
                  : []),
                {
                  label: t('schedule.aria', { name: asset.display_name }),
                  title: t('containers.column.schedule'),
                  value: asset.scan_schedule,
                  options: [
                    { value: 'off', label: t('schedule.off') },
                    { value: 'daily', label: t('schedule.daily') },
                    { value: 'weekly', label: t('schedule.weekly') },
                  ],
                  disabled: schedule.isPending,
                  onChange: (value: string) =>
                    schedule.mutate({
                      id: asset.id,
                      schedule: value as Asset['scan_schedule'],
                    }),
                },
              ]
        return (
          <div className="flex items-center justify-end gap-1 whitespace-nowrap">
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
            {asset === undefined ? null : (
              <ActionMenu
                label={t('containers.actions.aria', { name: asset.display_name })}
                // ponytail: the shared "⋯" trigger, turned upright.
                className="rotate-90"
                items={items}
                radio={radios}
              />
            )}
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
              const linkError =
                asset === undefined
                  ? undefined
                  : setLink.isError && setLink.variables?.imageId === asset.id
                    ? setLink.error
                    : clearLink.isError && clearLink.variables === asset.id
                      ? clearLink.error
                      : undefined
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
                  {linkError === undefined ? null : (
                    <tr>
                      <td colSpan={columns.length} className="pb-2">
                        <ErrorNote error={linkError} />
                      </td>
                    </tr>
                  )}
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
 * LinkedRepoCell shows the repository an image was built from, as one line:
 * `owner/repo` plus the source badge. `manual` is a user's choice and is never
 * overwritten by a later scan; `oci` came from the image's own labels. The
 * revision and the link controls live in the row's tooltip and menu.
 */
function LinkedRepoCell({ asset }: { asset: Asset | undefined }) {
  const t = useT()
  const link = asset?.linked_repo
  if (link === undefined) {
    return <span className="text-faint">—</span>
  }
  return (
    <span className="flex items-center gap-1.5 whitespace-nowrap">
      <span
        className="max-w-[22ch] truncate font-mono text-xs text-fg"
        title={
          link.revision === undefined
            ? `${link.ref} · ${link.source}`
            : `${link.ref} · ${t('containers.link.revision', {
                revision: link.revision,
              })} · ${link.source}`
        }
      >
        {link.ref}
      </span>
      <Badge tone={link.source === 'manual' ? 'neutral' : 'ok'}>
        {link.source}
      </Badge>
    </span>
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
