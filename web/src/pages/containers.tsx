import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'

import { assetsQuery, type Asset } from '../api/assets'
import { ApiError } from '../api/client'
import { dockerImagesQuery, useScanDockerImage, type DockerImage } from '../api/docker'
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
  const scanImage = useScanDockerImage()
  const start = useStartScans()

  const rows: ContainerRow[] =
    images.data?.images.map((image) => ({
      image,
      asset: assets.data?.find(
        (asset) => asset.kind === 'image' && asset.ref === image.reference,
      ),
    })) ?? []

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
    </>
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
