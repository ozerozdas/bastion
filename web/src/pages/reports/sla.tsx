import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'

import type { Finding } from '../../api/findings'
import {
  slaQuery,
  type SLAOverdueFinding,
} from '../../api/reports'
import { FindingDrawer } from '../../components/finding-drawer'
import { SlaThresholdEditor } from '../../components/sla-threshold-editor'
import { Badge } from '../../components/ui/badge'
import { severityLabel, severityTone } from '../../lib/finding-labels'
import { formatNumber, useT } from '../../lib/i18n'
import { formatDateTime } from '../../lib/time'
import { reportTrendDays, type ReportSearch } from '../../lib/urls'
import { cn } from '../../lib/utils'
import {
  ReportCaption,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  ReportStat,
  reportCardClass,
  useAssetNames,
  type ReportPanelProps,
} from './shared'

/** defaultSlaDays is the API's default fix window, shown as selected. */
const defaultSlaDays = 90

/**
 * SlaReportPanel is the SLA insights report (#190): open, overdue and fixed
 * counts for the window, the threshold editor, and the overdue findings table.
 * A threshold saved here is the same setting Configuration writes.
 */
export function SlaReportPanel({ search }: ReportPanelProps) {
  const t = useT()
  const navigate = useNavigate()
  const days = search.days ?? defaultSlaDays
  const report = useQuery(slaQuery({ assetId: search.asset, days }))
  const [openFinding, setOpenFinding] = useState<Finding | null>(null)

  function changeDays(next: number) {
    const value = next as (typeof reportTrendDays)[number]
    const nextSearch: ReportSearch = { ...search }
    if (value === defaultSlaDays) delete nextSearch.days
    else nextSearch.days = value
    void navigate({
      to: '/reports/$reportId',
      params: { reportId: 'sla' },
      search: nextSearch,
      replace: true,
    })
  }

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const data = report.data
  const overdue = [...data.overdue].sort(
    (left, right) => right.overdue_days - left.overdue_days,
  )

  return (
    <>
      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="flex flex-col gap-1">
            <ReportPanelHeading title={t('reports.sla.summary.title')} />
            <ReportCaption>{t('reports.sla.caption', { days })}</ReportCaption>
          </div>
          <div
            role="group"
            aria-label={t('reports.sla.days.aria')}
            className="flex items-center gap-1 rounded-md border border-border-subtle bg-bg p-0.5 print-hide"
          >
            {reportTrendDays.map((option) => {
              const active = days === option
              return (
                <button
                  key={option}
                  type="button"
                  aria-pressed={active}
                  onClick={() => changeDays(option)}
                  className={cn(
                    'rounded px-2.5 py-1 text-[0.8125rem] transition-colors',
                    active
                      ? 'bg-surface text-fg shadow-sm'
                      : 'text-muted hover:text-fg',
                  )}
                >
                  {t('reports.sla.days.option', { days: option })}
                </button>
              )
            })}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <ReportStat
            label={t('reports.sla.summary.open')}
            value={formatNumber(data.open_count)}
          />
          <ReportStat
            label={t('reports.sla.summary.overdue')}
            value={formatNumber(data.overdue_count)}
          />
          <ReportStat
            label={t('reports.sla.summary.fixed')}
            value={formatNumber(data.fixed_in_window)}
          />
          <ReportStat
            label={t('reports.sla.summary.meanTime')}
            value={
              data.mean_time_to_fix_days === null ||
              data.mean_time_to_fix_days === undefined
                ? '—'
                : formatNumber(data.mean_time_to_fix_days, {
                    maximumFractionDigits: 1,
                  })
            }
          />
        </div>
      </section>

      <section className={cn(reportCardClass, 'print-hide')}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading title={t('settings.sla.title')} />
          <ReportCaption>{t('settings.sla.description')}</ReportCaption>
        </div>
        <SlaThresholdEditor thresholds={data.thresholds} />
      </section>

      <section className={reportCardClass}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.sla.overdue.title')}
            aside={t('reports.sla.overdue.count', {
              count: data.overdue_count,
            })}
          />
          <ReportCaption>{t('reports.sla.overdue.caption')}</ReportCaption>
          {data.overdue_truncated ? (
            <ReportCaption>{t('reports.sla.overdue.truncated', { shown: overdue.length })}</ReportCaption>
          ) : null}
        </div>

        {overdue.length === 0 ? (
          <div className="flex flex-col gap-1 py-2">
            <p className="text-[0.875rem] font-medium">
              {t('reports.sla.overdue.empty.title')}
            </p>
            <p className="text-xs text-muted">
              {t('reports.sla.overdue.empty.body')}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[0.8125rem]">
              <thead className="text-xs text-faint">
                <tr>
                  <th className="border-b border-border-subtle pb-1.5 font-medium">
                    {t('reports.sla.column.finding')}
                  </th>
                  <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium sm:table-cell">
                    {t('reports.sla.column.project')}
                  </th>
                  <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium md:table-cell">
                    {t('reports.sla.column.firstSeen')}
                  </th>
                  <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                    {t('reports.sla.column.age')}
                  </th>
                  <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                    {t('reports.sla.column.threshold')}
                  </th>
                  <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                    {t('reports.sla.column.overdue')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {overdue.map((item) => (
                  <OverdueRow
                    key={`${String(item.finding.asset_id)}:${item.finding.fingerprint}`}
                    item={item}
                    onOpen={setOpenFinding}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {openFinding === null ? null : (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          onClose={() => setOpenFinding(null)}
        />
      )}
    </>
  )
}

/** OverdueRow is one overdue finding; its title opens the finding drawer. */
function OverdueRow({
  item,
  onOpen,
}: {
  item: SLAOverdueFinding
  onOpen: (finding: Finding) => void
}) {
  const finding = item.finding
  const nameOf = useAssetNames()

  return (
    <tr className="align-top hover:bg-hover">
      <td className="py-2 pr-3">
        <button
          type="button"
          onClick={() => onOpen(finding)}
          className="flex w-full min-w-0 items-center gap-2 rounded px-1 py-0.5 text-left transition-colors hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
        >
          <Badge tone={severityTone[finding.severity]}>
            {severityLabel(finding.severity)}
          </Badge>
          <span className="min-w-0 truncate">{finding.title}</span>
        </button>
      </td>
      <td className="hidden py-2 pl-3 text-muted sm:table-cell">
        {nameOf(finding.asset_id)}
      </td>
      <td className="hidden py-2 pl-3 text-xs whitespace-nowrap text-muted md:table-cell">
        {formatDateTime(item.first_seen)}
      </td>
      <td className="py-2 pl-3 tabular-nums">{formatNumber(item.age_days)}</td>
      <td className="py-2 pl-3 tabular-nums">
        {formatNumber(item.threshold_days)}
      </td>
      <td className="py-2 pl-3 font-medium text-critical tabular-nums">
        {formatNumber(item.overdue_days)}
      </td>
    </tr>
  )
}
