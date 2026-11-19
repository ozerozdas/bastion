import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { assetsQuery } from '../../api/assets'
import type { Finding } from '../../api/findings'
import type { SeverityTotals } from '../../api/reports'
import type { ReportSearch } from '../../lib/urls'
import { Badge } from '../../components/ui/badge'
import { ErrorNote } from '../../components/error-note'
import { severityLabel, severityTone } from '../../lib/finding-labels'
import { formatNumber, useT } from '../../lib/i18n'
import { cn } from '../../lib/utils'

/** ReportPanelProps is what ReportPage hands each report's panel. */
export type ReportPanelProps = {
  /** The report page's translated search: the project, advisory and window. */
  search: ReportSearch
}

/** reportCardClass is the surface every report panel sits on. */
export const reportCardClass =
  'flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4 sm:p-5'

/** ReportPanelHeading is a card's small heading with an optional right side. */
export function ReportPanelHeading({
  title,
  aside,
}: {
  title: ReactNode
  aside?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h2 className="text-[0.9375rem] font-semibold tracking-[-0.01em]">
        {title}
      </h2>
      {aside === undefined ? null : (
        <span className="text-xs text-muted tabular-nums">{aside}</span>
      )}
    </div>
  )
}

/** ReportCaption is the one-line explanation under a report's heading. */
export function ReportCaption({ children }: { children: ReactNode }) {
  return <p className="text-xs text-muted">{children}</p>
}

/** chipSeverities is the reading order of the recorded severity chips. */
const chipSeverities: {
  key: keyof SeverityTotals
  tone: 'critical' | 'high' | 'medium' | 'low' | 'neutral'
}[] = [
  { key: 'critical', tone: 'critical' },
  { key: 'high', tone: 'high' },
  { key: 'medium', tone: 'medium' },
  { key: 'low', tone: 'low' },
  { key: 'unknown', tone: 'neutral' },
]

/**
 * ReportSeverityChips shows the recorded counts as compact severity badges,
 * skipping zeroes; a scope with none reads as a dash.
 */
export function ReportSeverityChips({ counts }: { counts: SeverityTotals }) {
  const shown = chipSeverities.filter((severity) => counts[severity.key] > 0)
  if (shown.length === 0) {
    return (
      <span className="text-xs text-faint" aria-hidden="true">
        —
      </span>
    )
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((severity) => (
        <Badge
          key={severity.key}
          tone={severity.tone}
          className="tabular-nums"
        >
          {formatNumber(counts[severity.key])}
        </Badge>
      ))}
    </span>
  )
}

/** ReportStat is one number tile in a report's summary row. */
export function ReportStat({
  label,
  value,
  note,
}: {
  label: ReactNode
  value: ReactNode
  note?: ReactNode
}) {
  return (
    <div className="flex flex-col gap-0.5 rounded-card border border-border-subtle bg-surface px-3 py-2.5">
      <span className="text-xs text-muted">{label}</span>
      <span className="text-xl font-semibold tabular-nums">{value}</span>
      {note === undefined ? null : (
        <span className="text-[0.6875rem] text-faint">{note}</span>
      )}
    </div>
  )
}

/** ReportLoading is the panel a report shows while its query runs. */
export function ReportLoading() {
  const t = useT()
  return (
    <section className={reportCardClass}>
      <p className="text-muted">{t('reports.loading')}</p>
    </section>
  )
}

/** ReportErrorNote is the panel a failed report query shows. */
export function ReportError({ error }: { error: unknown }) {
  const t = useT()
  return (
    <section className={reportCardClass}>
      <ReportPanelHeading title={t('reports.failed')} />
      <ReportErrorText error={error} />
    </section>
  )
}

/** ReportErrorText is the inline error line, without a card around it. */
export function ReportErrorText({
  error,
  fix,
}: {
  error: unknown
  fix?: string
}) {
  const t = useT()
  return <ErrorNote error={error} fix={fix ?? t('reports.errorFix')} />
}

/** assetNames maps an asset id to its display name, falling back to the id. */
export function useAssetNames(): (assetId: number) => string {
  const t = useT()
  const assets = useQuery(assetsQuery)
  return (assetId) =>
    assets.data?.find((asset) => asset.id === assetId)?.display_name ??
    t('asset.fallback', { id: assetId })
}

/**
 * ReportFindings is the compact finding list the malware report and an OWASP
 * category share. A row is a button, so the existing FindingDrawer can open the
 * finding without leaving the report.
 */
export function ReportFindings({
  findings,
  onOpen,
  ariaLabel,
}: {
  findings: readonly Finding[]
  onOpen: (finding: Finding) => void
  ariaLabel: string
}) {
  const nameOf = useAssetNames()

  if (findings.length === 0) {
    return null
  }

  return (
    <ul aria-label={ariaLabel} className="divide-y divide-border-subtle">
      {findings.map((finding) => (
        <li key={`${String(finding.asset_id)}:${finding.fingerprint}`}>
          <button
            type="button"
            onClick={() => onOpen(finding)}
            className={cn(
              'flex w-full flex-col gap-0.5 rounded px-1 py-2 text-left transition-colors',
              'hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted',
            )}
          >
            <span className="flex min-w-0 items-center gap-2">
              <Badge tone={severityTone[finding.severity]}>
                {severityLabel(finding.severity)}
              </Badge>
              <span className="min-w-0 flex-1 truncate text-[0.8125rem]">
                {finding.title}
              </span>
              <span className="hidden max-w-[14rem] shrink-0 truncate text-xs text-muted sm:block">
                {nameOf(finding.asset_id)}
              </span>
            </span>
            <span className="flex min-w-0 flex-wrap items-center gap-x-2 text-xs text-faint">
              <span className="max-w-[14rem] truncate sm:hidden">
                {nameOf(finding.asset_id)}
              </span>
              {finding.rule_id === undefined ? null : (
                <span className="font-mono">{finding.rule_id}</span>
              )}
              {finding.package_name === undefined ? null : (
                <span className="truncate font-mono">
                  {finding.package_name}
                  {finding.package_version === undefined
                    ? ''
                    : `@${finding.package_version}`}
                </span>
              )}
              {finding.location === undefined ? null : (
                <span className="truncate">{finding.location}</span>
              )}
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}

/** ReportChevron is the disclosure marker of an expandable report row. */
export function ReportChevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 12 16"
      aria-hidden="true"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn(
        'size-3 shrink-0 text-faint transition-transform',
        open && 'rotate-180',
      )}
    >
      <path d="M2.5 6 6 9.5 9.5 6" />
    </svg>
  )
}
