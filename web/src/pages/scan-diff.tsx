import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { useMemo, useState, type SyntheticEvent } from 'react'

import { ApiError } from '../api/client'
import type { Finding } from '../api/findings'
import { openFindingTotal, type SeverityTotals } from '../api/reports'
import { scanDiffQuery, scanQuery, scansQuery } from '../api/scans'
import { DataTable, type DataTableColumn } from '../components/data-table'
import { ErrorNote } from '../components/error-note'
import { FindingDrawer } from '../components/finding-drawer'
import { BandHeader, BandSummary } from '../components/page-band'
import { SeverityCountBadges } from '../components/severity-counts'
import { Badge } from '../components/ui/badge'
import { severityLabel, severityTone } from '../lib/finding-labels'
import {
  compareBaselines,
  diffGroupEmptyText,
  parseScanIdParam,
  scanDiffSubtitle,
  type DiffGroup,
} from '../lib/scan-diff'
import { t, useT } from '../lib/i18n'
import { formatDateTime } from '../lib/time'
import { cn } from '../lib/utils'

/** diffGroups is the fixed order the page and its summary use. */
const diffGroups: { key: DiffGroup; labelKey: string }[] = [
  { key: 'new', labelKey: 'diff.group.new' },
  { key: 'fixed', labelKey: 'diff.group.fixed' },
  { key: 'persisting', labelKey: 'diff.group.persisting' },
]

/** The marker a row carries, so a group reads at a glance without its heading. */
const diffMarkers: Record<
  DiffGroup,
  { glyph: string; labelKey: string; className: string }
> = {
  new: { glyph: '＋', labelKey: 'diff.group.new', className: 'text-critical' },
  fixed: { glyph: '✓', labelKey: 'diff.group.fixed', className: 'text-ok' },
  persisting: {
    glyph: '•',
    labelKey: 'diff.group.persisting',
    className: 'text-faint',
  },
}

/** severityRows is the order the severity comparison reads in. */
const severityRows = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
] as const satisfies readonly (keyof SeverityTotals)[]

const selectClass =
  'h-8 max-w-[16rem] rounded-md border border-border-strong bg-surface px-2 text-[0.8125rem] text-fg'

/**
 * ScanDiffPage answers "what changed?" after a rescan (#17): the findings new,
 * fixed and persisting between one scan and another of the same project. Fixed
 * findings come from the older scan and are shown read-only.
 */
export function ScanDiffPage() {
  const t = useT()
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
  const [openFinding, setOpenFinding] = useState<Finding | null>(null)
  // New and fixed are what the reader came for; persisting is reference material
  // once the first two have been read.
  const [openGroups, setOpenGroups] = useState<Record<DiffGroup, boolean>>({
    new: true,
    fixed: true,
    persisting: false,
  })

  const options = useMemo(
    () => compareBaselines(baselines.data ?? [], scanId ?? 0),
    [baselines.data, scanId],
  )

  if (scanId === undefined) {
    return (
      <>
        <BandHeader>
          <BandSummary title={t('diff.noScan.title')} />
        </BandHeader>
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-xs text-muted">
            {t('diff.noScan.body', { example: '/scans/12/diff' })}
          </p>
        </section>
      </>
    )
  }

  const backToScans = (
    <Link
      to="/repositories"
      search={{ tab: 'scans', asset: scan.data?.asset_id }}
      className="text-xs text-muted hover:text-fg hover:underline"
    >
      {t('diff.back')}
    </Link>
  )

  if (scan.isError) {
    return (
      <>
        <BandHeader>
          <BandSummary
            above={backToScans}
            title={t('diff.title', { id: scanId })}
          />
        </BandHeader>
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.9375rem] font-semibold">
            {t('diff.failed')}
          </h2>
          <ErrorNote error={scan.error} />
        </section>
      </>
    )
  }

  const scannerNotes = (scan.data?.scanner_runs ?? []).filter(
    (run) => run.error || run.warning,
  )
  const title = t('diff.title', { id: scanId })

  return (
    <>
      <BandHeader>
        <BandSummary
          above={backToScans}
          title={title}
          subtitle={
            diff.data === undefined
              ? undefined
              : scanDiffSubtitle(diff.data.against_scan_id)
          }
          actions={
            <>
              <label htmlFor="scan-diff-against" className="sr-only">
                {t('diff.compareWith')}
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
                <option value="">{t('diff.previous')}</option>
                {options.map((option) => (
                  <option key={option.id} value={String(option.id)}>
                    #{option.id}
                    {option.started_at
                      ? ` — ${formatDateTime(option.started_at)}`
                      : ''}
                  </option>
                ))}
              </select>
            </>
          }
          below={
            <>
              {scannerNotes.length === 0 ? null : (
                <ul
                  aria-label={t('diff.warnings')}
                  className="mt-2 flex flex-col gap-1 text-[0.6875rem]"
                >
                  {scannerNotes.map((run) => (
                    <li
                      key={run.scanner}
                      className="flex flex-wrap items-baseline gap-1.5"
                    >
                      <span className="font-mono text-faint">
                        {run.scanner}
                      </span>
                      {run.error ? (
                        <span className="text-critical">{run.error}</span>
                      ) : null}
                      {run.warning ? (
                        <span className="text-medium">
                          {t('diff.warning', { warning: run.warning })}
                        </span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {diff.data === undefined ? null : (
                <DiffOverview
                  counts={diff.data.counts}
                  againstId={diff.data.against_scan_id}
                  scanId={scanId}
                />
              )}
            </>
          }
        />
      </BandHeader>

      <section aria-label={title} className="flex flex-col gap-3">
        {diff.isPending ? (
          <p className="text-muted">{t('diff.loading')}</p>
        ) : null}

        {diff.isError ? (
          <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
            <h2 className="text-[0.8125rem] font-semibold">
              {t('diff.changesFailed')}
            </h2>
            <ErrorNote error={diff.error} fix={diffErrorFix(diff.error)} />
          </section>
        ) : null}

        {diff.isSuccess ? (
          <div className="flex flex-col rounded-card border border-border-subtle bg-surface px-4">
            {diffGroups.map((group) => {
              const rows = diff.data[group.key]
              const headingId = `diff-${group.key}`
              return (
                <section
                  key={group.key}
                  aria-labelledby={headingId}
                  className="border-t border-border-subtle first:border-t-0"
                >
                  <details
                    open={openGroups[group.key]}
                    onToggle={(event: SyntheticEvent<HTMLDetailsElement>) => {
                      const open = event.currentTarget.open
                      setOpenGroups((current) =>
                        current[group.key] === open
                          ? current
                          : { ...current, [group.key]: open },
                      )
                    }}
                    className="group"
                  >
                    <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5 [&::-webkit-details-marker]:hidden">
                      <span
                        aria-hidden="true"
                        className="text-faint transition-transform group-open:rotate-90"
                      >
                        ›
                      </span>
                      <h2
                        id={headingId}
                        className="text-[0.8125rem] font-semibold"
                      >
                        {t('diff.group.heading', { group: t(group.labelKey) })}
                      </h2>
                      <span className="text-xs text-faint tabular-nums">
                        {t('diff.group.count', { count: rows.length })}
                      </span>
                      <span className="ml-auto">
                        <SeverityCountBadges
                          counts={diff.data.counts[group.key]}
                        />
                      </span>
                    </summary>
                    <div className="pb-3">
                      {rows.length === 0 ? (
                        <p className="text-xs text-muted">
                          {diffGroupEmptyText(group.key)}
                        </p>
                      ) : (
                        <DataTable
                          rows={rows}
                          columns={diffColumns(group.key)}
                          rowKey={(finding) => finding.fingerprint}
                          onRowActivate={(finding) => setOpenFinding(finding)}
                        />
                      )}
                    </div>
                  </details>
                </section>
              )
            })}
          </div>
        ) : null}
      </section>

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

/** addTotals folds two severity totals into one. */
function addTotals(left: SeverityTotals, right: SeverityTotals): SeverityTotals {
  return {
    critical: left.critical + right.critical,
    high: left.high + right.high,
    medium: left.medium + right.medium,
    low: left.low + right.low,
    unknown: left.unknown + right.unknown,
  }
}

/**
 * DiffOverview is the band's reading of the diff: the three group totals as
 * large figures, then the same findings split by severity before and after,
 * then two thin bars drawn to one scale so the two scans can be compared by
 * shape as well as by number. Before is the older scan (fixed + persisting),
 * after the scan on screen (new + persisting).
 */
function DiffOverview({
  counts,
  againstId,
  scanId,
}: {
  counts: { new: SeverityTotals; fixed: SeverityTotals; persisting: SeverityTotals }
  againstId?: number
  scanId: number
}) {
  const t = useT()
  const before = addTotals(counts.fixed, counts.persisting)
  const after = addTotals(counts.new, counts.persisting)
  const beforeTotal = openFindingTotal(before)
  const afterTotal = openFindingTotal(after)
  const max = Math.max(beforeTotal, afterTotal)
  const changes = severityRows.filter(
    (severity) => before[severity] > 0 || after[severity] > 0,
  )

  return (
    <div className="mt-3 flex flex-col gap-3 border-t border-border-subtle pt-3">
      <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
        <dl
          aria-label={t('diff.figures')}
          className="flex flex-wrap items-end gap-x-7 gap-y-2"
        >
          <Figure
            label={t('diff.group.new')}
            value={openFindingTotal(counts.new)}
            className="text-critical"
          />
          <Figure
            label={t('diff.group.fixed')}
            value={openFindingTotal(counts.fixed)}
            className="text-ok"
          />
          <Figure
            label={t('diff.group.persisting')}
            value={openFindingTotal(counts.persisting)}
            className="text-muted"
          />
        </dl>

        {changes.length === 0 ? null : (
          <ul
            aria-label={t('diff.severity.aria')}
            className="flex flex-col gap-0.5 text-[0.6875rem]"
          >
            {changes.map((severity) => {
              const delta = after[severity] - before[severity]
              return (
                <li
                  key={severity}
                  className="flex items-center gap-2 whitespace-nowrap"
                >
                  <span className="w-[4.6rem] shrink-0 text-faint">
                    {severityLabel(severity)}
                  </span>
                  <span className="tabular-nums text-muted">
                    {before[severity]}
                    <span aria-hidden="true"> → </span>
                    {after[severity]}
                  </span>
                  <span
                    aria-hidden="true"
                    className={cn(
                      'w-7 text-right font-medium tabular-nums',
                      delta < 0
                        ? 'text-ok'
                        : delta > 0
                          ? 'text-critical'
                          : 'text-faint',
                    )}
                  >
                    {delta === 0 ? '–' : delta < 0 ? `↓${-delta}` : `↑${delta}`}
                  </span>
                  <span className="sr-only">
                    {delta === 0
                      ? t('diff.severity.same')
                      : delta < 0
                        ? t('diff.severity.down', { count: -delta })
                        : t('diff.severity.up', { count: delta })}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {max === 0 ? null : (
        <>
          <div aria-hidden="true" className="flex flex-col gap-1">
            {againstId === undefined ? null : (
              <CompareBarRow
                id={againstId}
                total={beforeTotal}
                segments={[
                  {
                    count: openFindingTotal(counts.fixed),
                    className: 'bg-ok',
                  },
                  {
                    count: openFindingTotal(counts.persisting),
                    className: 'bg-border-strong',
                  },
                ]}
                max={max}
              />
            )}
            <CompareBarRow
              id={scanId}
              total={afterTotal}
              segments={[
                { count: openFindingTotal(counts.new), className: 'bg-critical' },
                {
                  count: openFindingTotal(counts.persisting),
                  className: 'bg-border-strong',
                },
              ]}
              max={max}
            />
          </div>
          <p className="sr-only">
            {againstId === undefined
              ? t('diff.bar.aria.first', { scan: scanId, after: afterTotal })
              : t('diff.bar.aria', {
                  against: againstId,
                  scan: scanId,
                  before: beforeTotal,
                  after: afterTotal,
                })}
          </p>
        </>
      )}
    </div>
  )
}

/** Figure is one large number in the band with its small label above it. */
function Figure({
  label,
  value,
  className,
}: {
  label: string
  value: number
  className: string
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[0.6875rem] tracking-[0.08em] text-faint uppercase">
        {label}
      </dt>
      <dd className={cn('text-xl leading-none font-semibold tabular-nums', className)}>
        {value}
      </dd>
    </div>
  )
}

/** A bar's segment: how many findings it stands for and the colour it uses. */
type BarSegment = { count: number; className: string }

/**
 * CompareBarRow is one scan's total as a thin stacked bar. Both scans are
 * drawn against the same maximum, so the shorter bar reads as fewer findings;
 * fixed segments are green, new ones red, and persisting findings stay neutral
 * because they are in both scans.
 */
function CompareBarRow({
  id,
  total,
  segments,
  max,
}: {
  id: number
  total: number
  segments: readonly BarSegment[]
  max: number
}) {
  const t = useT()
  return (
    <div className="flex items-center gap-2">
      <span className="w-9 shrink-0 text-right font-mono text-[0.625rem] text-faint tabular-nums">
        <span aria-hidden="true">#{id}</span>
        <span className="sr-only">{t('diff.bar.scan', { id })}</span>
      </span>
      <span className="flex h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-hover">
        {segments.map((segment, index) =>
          segment.count === 0 ? null : (
            <span
              key={index}
              style={{ width: `${(segment.count / max) * 100}%` }}
              className={segment.className}
            />
          ),
        )}
      </span>
      <span className="w-6 shrink-0 text-right text-[0.625rem] text-muted tabular-nums">
        {total}
      </span>
    </div>
  )
}

/**
 * diffColumns is the diff table's row: the marker for its group, severity, the
 * finding with its rule id, where it was found, and the scanner that reported
 * it. The project is not a column: a diff compares one project with itself.
 */
function diffColumns(group: DiffGroup): DataTableColumn<Finding>[] {
  const marker = diffMarkers[group]
  return [
    {
      id: 'marker',
      header: <span className="sr-only">{t('diff.column.change')}</span>,
      headerClassName: 'w-6 pl-3',
      cellClassName: 'py-1.5 pr-1 pl-3 align-middle',
      cell: () => (
        <span
          className={cn('text-[0.8125rem] leading-none', marker.className)}
        >
          <span aria-hidden="true">{marker.glyph}</span>
          <span className="sr-only">{t(marker.labelKey)}</span>
        </span>
      ),
    },
    {
      id: 'severity',
      header: t('findings.column.severity'),
      headerClassName: 'pl-3',
      cellClassName: 'py-1.5 pr-3 pl-3 whitespace-nowrap',
      cell: (finding) => (
        <Badge tone={severityTone[finding.severity]}>
          {severityLabel(finding.severity)}
        </Badge>
      ),
    },
    {
      id: 'finding',
      header: t('findings.column.finding'),
      headerClassName: 'pl-3',
      cellClassName: 'max-w-[28rem] py-1.5 pr-3 pl-3',
      cellTitle: (finding) =>
        finding.rule_id === undefined
          ? finding.title
          : `${finding.title} — ${finding.rule_id}`,
      cell: (finding) => (
        <span className="flex min-w-0 items-baseline gap-2">
          <span className="min-w-0 truncate">{finding.title}</span>
          {finding.rule_id === undefined ? null : (
            <span className="shrink-0 font-mono text-xs text-muted">
              {finding.rule_id}
            </span>
          )}
        </span>
      ),
    },
    {
      id: 'location',
      header: t('diff.column.location'),
      headerClassName: 'pl-3',
      cellClassName: 'max-w-[26rem] py-1.5 pr-3 pl-3',
      cellTitle: (finding) => packageOrLocation(finding) ?? undefined,
      cell: (finding) => {
        const value = packageOrLocation(finding)
        return value === undefined ? (
          <span className="text-faint">—</span>
        ) : (
          <span className="block truncate font-mono text-xs text-muted">
            {value}
          </span>
        )
      },
    },
    {
      id: 'scanner',
      header: t('diff.column.scanner'),
      headerClassName: 'pl-3',
      cellClassName:
        'py-1.5 pr-3 pl-3 whitespace-nowrap font-mono text-xs text-muted',
      cell: (finding) => finding.scanner,
    },
  ]
}

/** packageOrLocation prefers the package a fix names, then where it was seen. */
function packageOrLocation(finding: Finding): string | undefined {
  if (finding.package_name !== undefined) {
    return finding.package_version === undefined
      ? finding.package_name
      : `${finding.package_name}@${finding.package_version}`
  }
  return finding.location
}

/** diffErrorFix explains the one status the page can do something about. */
function diffErrorFix(error: unknown): string | undefined {
  return error instanceof ApiError && error.status === 409
    ? t('diff.onlySucceeded')
    : undefined
}
