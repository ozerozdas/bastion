import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'

import {
  assetsQuery,
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
import { useStartScans, type Scan } from '../api/scans'
import {
  DataTable,
  type DataTableColumn,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { SeverityCountBadges } from '../components/severity-counts'
import { relativeTime } from '../lib/time'

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
 * ContainersPage lists the local Docker daemon's images and lets one be
 * scanned. A tracked image also shows its last scan and findings, the way a
 * project row does.
 */
export function ContainersPage() {
  const images = useQuery(dockerImagesQuery)
  const assets = useQuery(assetsQuery)
  const connections = useQuery(connectionsQuery)
  const scanImage = useScanDockerImage()
  const start = useStartScans()

  const rows: ContainerRow[] =
    images.data?.images.map((image) => ({
      image,
      asset: assets.data?.find(
        (asset) => asset.kind === 'image' && asset.ref === image.reference,
      ),
    })) ?? []
  // The link control offers the tracked repositories.
  const repos = (assets.data ?? []).filter((asset) => asset.kind === 'repo')

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
      cell: (row) => <ScanCell asset={row.asset} />,
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
        const running =
          row.asset?.last_scan?.status === 'queued' ||
          row.asset?.last_scan?.status === 'running'
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
            {row.asset ? (
              <Link
                to="/findings"
                search={{ asset: row.asset.id }}
                className={buttonVariants({ variant: 'ghost', size: 'sm' })}
              >
                View findings
              </Link>
            ) : null}
          </div>
        )
      },
    },
  ]

  return (
    <>
      {images.isSuccess ? (
        <p className="text-xs text-faint">Local Docker images</p>
      ) : null}

      {images.isError ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <ErrorNote error={images.error} />
        </section>
      ) : null}
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

      {images.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">Looking for a Docker daemon…</p>
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
          />
        </section>
      ) : null}

      <EcrSection
        assets={assets.data ?? []}
        connections={connections.data ?? []}
        pending={connections.isPending}
      />    </>
  )
}

/**
 * EcrSection lists ECR repositories for every AWS connection, next to the
 * local Docker images. A machine without an AWS connection gets a hint that
 * links to Connections → Registry.
 */
function EcrSection({
  assets,
  connections,
  pending,
}: {
  assets: Asset[]
  connections: Connection[]
  pending: boolean
}) {
  const aws = connections.filter((connection) => connection.kind === 'aws')

  return (
    <section aria-label="ECR" className="space-y-3">
      <p className="text-xs text-faint">ECR images</p>
      {pending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">Looking for an AWS connection…</p>
        </section>
      ) : null}
      {!pending && aws.length === 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-sm text-muted">
            No AWS connection yet. Add one in{' '}
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
      ) : null}
      {aws.map((connection) => (
        <EcrConnection
          key={connection.id}
          connection={connection}
          assets={assets}
          repos={assets.filter((asset) => asset.kind === 'repo')}
        />
      ))}
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
}: {
  connection: Connection
  assets: Asset[]
  repos: Asset[]
}) {
  const discover = useQuery(ecrDiscoverQuery(connection.id))
  const scan = useScanEcrImage(connection.id)

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
      cell: (row) => <ScanCell asset={row.asset} />,
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
        const running =
          row.asset?.last_scan?.status === 'queued' ||
          row.asset?.last_scan?.status === 'running'
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
                ? 'Queueing…'
                : row.asset
                  ? 'Scan'
                  : 'Add & scan'}
            </Button>
            {row.asset ? (
              <Link
                to="/findings"
                search={{ asset: row.asset.id }}
                className={buttonVariants({ variant: 'ghost', size: 'sm' })}
              >
                View findings
              </Link>
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

/** ScanCell shows the tracked asset's last scan, or that it is not tracked. */
function ScanCell({ asset }: { asset: Asset | undefined }) {
  if (!asset) {
    return <Badge>not tracked</Badge>
  }
  if (!asset.last_scan) {
    return <Badge>never scanned</Badge>
  }
  return (
    <span className="inline-flex items-center gap-2">
      <Badge tone={statusTone[asset.last_scan.status]}>
        {asset.last_scan.status}
      </Badge>
      <span className="text-xs text-faint">
        {asset.last_scan.finished_at
          ? relativeTime(asset.last_scan.finished_at)
          : ''}
      </span>
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
