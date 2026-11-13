import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { useMemo, useState } from 'react'

import { assetsQuery } from '../api/assets'
import { ApiError } from '../api/client'
import type { Finding } from '../api/findings'
import { scanDiffQuery, scanQuery, scansQuery } from '../api/scans'
import type { SeverityTotals } from '../api/reports'
import { DataTable } from '../components/data-table'
import { ErrorNote } from '../components/error-note'
import { FindingDrawer } from '../components/finding-drawer'
import { SeverityCountBadges } from '../components/severity-counts'
import {
  compareBaselines,
  diffGroupEmptyText,
  parseScanIdParam,
  scanDiffSubtitle,
  type DiffGroup,
} from '../lib/scan-diff'
import { formatDateTime } from '../lib/time'
import { findingColumns } from './findings'

/** diffGroups is the fixed order the page and its summary use. */
const diffGroups: { key: DiffGroup; label: string }[] = [
  { key: 'new', label: 'New' },
  { key: 'fixed', label: 'Fixed' },
  { key: 'persisting', label: 'Persisting' },
]

const selectClass =
  'h-8 rounded-md border border-border-strong bg-surface px-2 text-[13px] text-fg'

/**
 * ScanDiffPage answers "what changed?" after a rescan (#17): the findings new,
 * fixed and persisting between one scan and another of the same project. Fixed
 * findings come from the older scan and are shown read-only.
 */
export function ScanDiffPage() {
  const { scanId: rawScanId } = useParams({ from: '/scans/$scanId/diff' })
  const { against } = useSearch({ from: '/scans/$scanId/diff' })
  const navigate = useNavigate()
  const scanId = parseScanIdParam(rawScanId)

  const scan = useQuery({
    ...scanQuery(scanId ?? 0),
    enabled: scanId !== undefined,
  })
  const diff = useQuery({
    ...scanDiffQuery(scanId ?? 0, against),
    enabled: scanId !== undefined,
  })
  const baselines = useQuery({
    ...scansQuery(scan.data?.asset_id),
    enabled: scan.data !== undefined,
  })
  const assets = useQuery(assetsQuery)
  const [openFinding, setOpenFinding] = useState<Finding | null>(null)

  const assetNames = useMemo(
    () =>
      new Map(
        (assets.data ?? []).map((asset) => [asset.id, asset.display_name]),
      ),
    [assets.data],
  )
  const columns = useMemo(() => findingColumns(assetNames), [assetNames])
  const options = useMemo(
    () => compareBaselines(baselines.data ?? [], scanId ?? 0),
    [baselines.data, scanId],
  )

  if (scanId === undefined) {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[15px] font-semibold">No such scan</h2>
        <p className="text-xs text-muted">
          A scan comparison needs a scan id in the URL, like{' '}
          <span className="font-mono">/scans/12/diff</span>.
        </p>
      </section>
    )
  }

  const backToScans = (
    <Link
      to="/projects"
      search={{ tab: 'scans', asset: scan.data?.asset_id }}
      className="text-xs text-muted hover:text-fg hover:underline"
    >
      ← Scans
    </Link>
  )

  if (scan.isError) {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[15px] font-semibold">Scan failed to load</h2>
        <ErrorNote error={scan.error} />
        {backToScans}
      </section>
    )
  }

  return (
    <>
      <section
        aria-labelledby="scan-diff-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2
            id="scan-diff-heading"
            className="text-[15px] font-semibold tracking-[-0.01em]"
          >
            Changes in scan #{String(scanId)}
          </h2>
          {diff.data === undefined ? null : (
            <span className="text-faint">
              {scanDiffSubtitle(diff.data.against_scan_id)}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {backToScans}
          <label htmlFor="scan-diff-against" className="ml-2 text-xs text-muted">
            Compare with
          </label>
          <select
            id="scan-diff-against"
            value={against === undefined ? '' : String(against)}
            onChange={(event) => {
              setOpenFinding(null)
              void navigate({
                to: '/scans/$scanId/diff',
                params: { scanId: String(scanId) },
                search:
                  event.target.value === ''
                    ? {}
                    : { against: Number(event.target.value) },
                replace: true,
              })
            }}
            className={selectClass}
          >
            <option value="">Previous succeeded scan</option>
            {options.map((option) => (
              <option key={option.id} value={String(option.id)}>
                #{option.id}
                {option.started_at ? ` — ${formatDateTime(option.started_at)}` : ''}
              </option>
            ))}
          </select>
        </div>

        {diff.isPending ? <p className="text-muted">Loading changes…</p> : null}

        {diff.isError ? (
          <div className="flex flex-col gap-1">
            <h3 className="text-[13px] font-semibold">Changes failed to load</h3>
            <ErrorNote error={diff.error} fix={diffErrorFix(diff.error)} />
          </div>
        ) : null}
      </section>

      {diff.isSuccess ? (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            {diffGroups.map((group) => (
              <DiffSummary
                key={group.key}
                label={group.label}
                counts={diff.data.counts[group.key]}
              />
            ))}
          </div>

          {diffGroups.map((group) => {
            const rows = diff.data[group.key]
            return (
              <section
                key={group.key}
                aria-labelledby={`diff-${group.key}`}
                className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
              >
                <div className="flex flex-wrap items-baseline gap-2.5">
                  <h2 id={`diff-${group.key}`} className="text-[13px] font-semibold">
                    {group.label} findings
                  </h2>
                  <span className="text-faint tabular-nums">
                    {rows.length === 1 ? '1 finding' : `${String(rows.length)} findings`}
                  </span>
                </div>
                {rows.length === 0 ? (
                  <p className="text-xs text-muted">
                    {diffGroupEmptyText(group.key)}
                  </p>
                ) : (
                  <DataTable
                    rows={rows}
                    columns={columns}
                    rowKey={(finding) => finding.fingerprint}
                    onRowActivate={(finding) => setOpenFinding(finding)}
                  />
                )}
              </section>
            )
          })}
        </>
      ) : null}

      {openFinding ? (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          readOnly={openFinding.scan_id !== scanId}
          onClose={() => setOpenFinding(null)}
        />
      ) : null}
    </>
  )
}

/** DiffSummary is one group's counts, in the same badges the scans table uses. */
function DiffSummary({
  label,
  counts,
}: {
  label: string
  counts: SeverityTotals
}) {
  return (
    <section className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4">
      <h2 className="text-[13px] font-semibold">{label}</h2>
      <SeverityCountBadges counts={counts} />
    </section>
  )
}

/** diffErrorFix explains the one status the page can do something about. */
function diffErrorFix(error: unknown): string | undefined {
  return error instanceof ApiError && error.status === 409
    ? 'Only a succeeded scan can be compared.'
    : undefined
}
