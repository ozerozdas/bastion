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
import { useStartScans, type Scan } from '../api/scans'
import {
  DataTable,
  DataTableRow,
  type DataTableColumn,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { SeverityCountBadges } from '../components/severity-counts'
import { Tabs, type TabItem } from '../components/ui/tabs'
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
    tabs.push({ value: 'docker', label: 'Docker' })
  }
  for (const connection of aws) {
    tabs.push({
      value: `aws-${connection.id}`,
      label: `AWS (${connection.name})`,
    })
  }
  if (orphaned.length > 0) {
    tabs.push({ value: 'orphaned', label: 'Orphaned' })
  }
  // The first tab is the bare path, as on the other tabbed pages; a stale tab
  // (?tab=aws-9 once that connection is gone) falls back to it.
  const tab =
    tabs.find((item) => item.value === search.tab)?.value ?? tabs[0]?.value
  const connection = aws.find((item) => `aws-${item.id}` === tab)

  if (images.isPending || connections.isPending) {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">Looking for container sources…</p>
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
            title="No Docker daemon found"
            body="Start Docker, OrbStack or Colima, then reload this page. Bastion only reads images the daemon already holds."
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
        label="Container sources"
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
  const images = useQuery(dockerImagesQuery)
  const scanImage = useScanDockerImage()
  const start = useStartScans()
  const archive = useArchiveAsset()
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
      header: 'Image',
      cell: (row) => (
        <div className="max-w-[32ch]">
          <span
            className="block truncate font-mono text-xs text-fg"
            title={row.image.reference}
          >
            {row.image.reference}
          </span>
          <span className="block truncate font-mono text-[11px] text-faint">
            {shortID(row.image.id)}
          </span>
        </div>
      ),
    },
    {
      id: 'size',
      header: 'Size',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap',
      cell: (row) => <span className="text-muted">{formatSize(row.image.size_bytes)}</span>,
    },
    {
      id: 'created',
      header: 'Created',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap',
      cell: (row) => (
        <span className="text-muted">{relativeTime(row.image.created_at)}</span>
      ),
    },
    {
      id: 'last-scan',
      header: 'Last scan',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap',
      cell: (row) => (
        <ScanCell
          asset={row.asset}
          live={row.asset ? live.get(row.asset.id) : undefined}
        />
      ),
    },
    {
      id: 'repository',
      header: 'Repository',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      cell: (row) => <LinkCell asset={row.asset} repos={repos} />,
    },
    {
      id: 'open-findings',
      header: 'Open findings',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      cell: (row) =>
        row.asset ? (
          <SeverityCountBadges counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: 'Actions',
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
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
              {scanning(row) ? 'Queueing…' : 'Scan'}
            </Button>
            {asset ? (
              <>
                <Link
                  to="/findings"
                  search={{ asset: asset.id }}
                  className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                >
                  View findings
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
                  Remove
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
          title="No Docker daemon found"
          body="Start Docker, OrbStack or Colima, then reload this page. Bastion only reads images the daemon already holds."
        />
      ) : null}

      {images.isSuccess &&
      images.data.available &&
      images.data.images.length === 0 ? (
        <EmptyState
          title="No tagged images yet"
          body="Pull or build an image, then reload this page. Bastion never pulls, builds or runs anything itself."
        />
      ) : null}

      {images.isSuccess && images.data.available && rows.length > 0 ? (
        <section
          aria-label="Containers"
          className="rounded-card border border-border-subtle bg-surface p-4"
        >
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(row) => `${row.image.reference}-${row.image.id}`}
            renderRow={(row) => {
              const asset = row.asset
              return (
                <Fragment>
                  <DataTableRow>
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        className={column.cellClassName}
                        title={column.cellTitle?.(row)}
                      >
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
  return (
    <section className="rounded-card border border-border-subtle bg-surface p-4">
      <p className="text-sm text-muted">
        <span>No AWS connection yet.</span> Add one in{' '}
        <Link
          to="/connections"
          search={{ tab: 'registry' }}
          className="underline underline-offset-2 hover:text-fg"
        >
          Connections → Registry
        </Link>{' '}
        to list ECR images.
      </p>
    </section>
  )
}

/**
 * OrphanedImages lists ECR images whose AWS connection was removed. They no
 * longer appear under any connection, so this is where they can be archived.
 */
function OrphanedImages({ assets }: { assets: Asset[] }) {
  const archive = useArchiveAsset()

  const columns: DataTableColumn<Asset>[] = [
    {
      id: 'image',
      header: 'Image',
      cell: (asset) => (
        <div className="max-w-[40ch]">
          <span
            className="block truncate font-mono text-xs text-fg"
            title={asset.ref}
          >
            {asset.display_name}
          </span>
          <span className="block truncate font-mono text-[11px] text-faint">
            {asset.ref}
          </span>
        </div>
      ),
    },
    {
      id: 'open-findings',
      header: 'Open findings',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      cell: (asset) => <SeverityCountBadges counts={asset.open_counts} />,
    },
    {
      id: 'actions',
      header: 'Actions',
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
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
              {archiving ? 'Archiving…' : 'Archive'}
            </Button>
          </div>
        )
      },
    },
  ]

  return (
    <section aria-label="Orphaned ECR images" className="space-y-2">
      <p className="text-xs text-muted">
        Images whose AWS connection was removed. Archiving one hides its
        findings; its scan history stays.
      </p>
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
  const discover = useQuery(ecrDiscoverQuery(connection.id))
  const scan = useScanEcrImage(connection.id)
  const archive = useArchiveAsset()
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
      header: 'Image',
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
            <span className="block truncate font-mono text-[11px] text-faint">
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
      header: 'Pushed',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap',
      cell: (row) => (
        <span className="text-muted">{relativeTime(row.tag.pushed_at)}</span>
      ),
    },
    {
      id: 'last-scan',
      header: 'Last scan',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top whitespace-nowrap',
      cell: (row) => (
        <ScanCell
          asset={row.asset}
          live={row.asset ? live.get(row.asset.id) : undefined}
        />
      ),
    },
    {
      id: 'repository',
      header: 'Repository',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      cell: (row) => <LinkCell asset={row.asset} repos={repos} />,
    },
    {
      id: 'open-findings',
      header: 'Open findings',
      headerClassName: 'pl-3',
      cellClassName: 'pl-3 align-top',
      cell: (row) =>
        row.asset ? (
          <SeverityCountBadges counts={row.asset.open_counts} />
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      id: 'actions',
      header: 'Actions',
      headerClassName: 'pl-3 text-right',
      cellClassName: 'pl-3 align-top',
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
              {scanning(row) ? 'Queueing…' : asset ? 'Scan' : 'Add & scan'}
            </Button>
            {asset ? (
              <>
                <Link
                  to="/findings"
                  search={{ asset: asset.id }}
                  className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                >
                  View findings
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
                  Remove
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
      <h2 className="text-[13px] font-semibold">
        {connection.name}
        {connection.region ? (
          <span className="ml-2 font-mono text-[11px] font-normal text-faint">
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
          <p className="text-muted">Listing ECR repositories…</p>
        </section>
      ) : null}
      {discover.isSuccess && rows.length === 0 ? (
        <EmptyState
          title="No ECR tags found"
          body="This AWS connection's repositories have no tagged images yet."
        />
      ) : null}
      {rows.length > 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(row) => row.tag.ref}
            renderRow={(row) => {
              const asset = row.asset
              return (
                <Fragment>
                  <DataTableRow>
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        className={column.cellClassName}
                        title={column.cellTitle?.(row)}
                      >
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
              className="font-mono text-[11px] text-faint"
              title={`revision ${asset.linked_repo.revision}`}
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
            {clearLink.isPending ? 'Unlinking…' : 'Unlink'}
          </Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-1.5">
          <select
            aria-label={`Link ${asset.display_name} to a repository`}
            value={choice}
            onChange={(event) => setChoice(event.target.value)}
            className="h-7 max-w-[18ch] rounded-md border border-border-strong bg-surface px-1.5 text-[12px] text-fg"
          >
            <option value="">Link to…</option>
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
            {setLink.isPending ? 'Linking…' : 'Link'}
          </Button>
        </div>
      )}
      {error ? (
        <span role="alert" className="text-[11px] text-critical">
          {error instanceof ApiError ? error.message : 'the link request failed'}
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
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
      <span>
        Remove “{name}”? Its findings are hidden and it leaves this list;
        scanning it again brings it back.
      </span>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="text-critical"
        onClick={onRemove}
        disabled={pending}
      >
        {pending ? 'Removing…' : 'Remove'}
      </Button>
      <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
        Cancel
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
  if (!asset) {
    return <Badge>not tracked</Badge>
  }
  const lastScan = asset.last_scan
  // A live event wins over the list row until the finished event refetches it.
  const active = isLiveActive(live)
  const status = active && live ? live.status : lastScan?.status
  if (!status) {
    return <Badge>never scanned</Badge>
  }
  return (
    <span className="inline-flex items-center gap-2">
      <Badge tone={statusTone[status]}>{status}</Badge>
      <span className="text-xs text-faint">
        {active
          ? 'in progress'
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
    return `${(mib / 1024).toFixed(1)} GiB`
  }
  return `${String(Math.max(1, Math.round(mib)))} MiB`
}

/** ErrorNote shows a failed request with a human cause. */
function ErrorNote({ error }: { error: unknown }) {
  const cause =
    error instanceof ApiError
      ? error.message
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
