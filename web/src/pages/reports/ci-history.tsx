import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { ciHistoryQuery, type CIRun } from '../../api/reports'
import { EmptyState } from '../../components/empty-state'
import { Badge } from '../../components/ui/badge'
import { useT } from '../../lib/i18n'
import { ciFailOnLevels, runFails, type CIFailOn } from '../../lib/report-ci'
import { formatDateTime } from '../../lib/time'
import {
  ReportCaption,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  ReportSeverityChips,
  reportCardClass,
  type ReportPanelProps,
} from './shared'

/** ciHistoryLimit is the number of newest runs the table shows. */
const ciHistoryLimit = 50

/**
 * CIHistoryReportPanel is the CI scan history (#190): the runs pipelines
 * started, with their outcome. The fail-on selector only changes how the
 * badge reads, so a pipeline's threshold can be previewed against the history.
 */
export function CIHistoryReportPanel({ search }: ReportPanelProps) {
  const t = useT()
  const report = useQuery(
    ciHistoryQuery({ assetId: search.asset, limit: ciHistoryLimit }),
  )
  const [failOn, setFailOn] = useState<CIFailOn>('none')

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const runs = report.data.runs
  if (runs.length === 0) {
    return (
      <EmptyState
        title={t('reports.ci-history.empty.title')}
        body={t('reports.ci-history.empty.body')}
      />
    )
  }

  const failed = runs.filter((run) => runFails(run, failOn)).length

  /** durationText renders a run's duration in the shortest readable unit. */
  function durationText(ms: number | null): string {
    if (ms === null) return '—'
    const seconds = Math.max(0, Math.round(ms / 1000))
    if (seconds < 60) return t('time.seconds', { seconds })
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) {
      return t('time.minutes', { minutes, seconds: seconds % 60 })
    }
    const hours = Math.floor(minutes / 60)
    return t('time.hours', { hours, minutes: minutes % 60 })
  }

  return (
    <section className={reportCardClass}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.ci-history.table.title')}
            aside={t('reports.ci-history.failed', { count: failed })}
          />
          <ReportCaption>{t('reports.ci-history.caption')}</ReportCaption>
        </div>
        <div className="flex flex-col gap-1 print-hide">
          <label
            htmlFor="ci-fail-on"
            className="text-xs font-medium text-muted"
          >
            {t('reports.ci-history.failOn.label')}
          </label>
          <select
            id="ci-fail-on"
            value={failOn}
            onChange={(event) => setFailOn(event.target.value as CIFailOn)}
            className="h-8 min-w-40 rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
          >
            {ciFailOnLevels.map((level) => (
              <option key={level} value={level}>
                {t(`reports.ci-history.failOn.${level}`)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[0.8125rem]">
          <thead className="text-xs text-faint">
            <tr>
              <th className="border-b border-border-subtle pb-1.5 font-medium">
                {t('reports.ci-history.column.project')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.ci-history.column.trigger')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.ci-history.column.status')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.ci-history.column.started')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.ci-history.column.duration')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.ci-history.column.findings')}
              </th>
              <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium sm:table-cell">
                {t('reports.ci-history.column.scanners')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {runs.map((run) => (
              <RunRow
                key={run.scan_id}
                run={run}
                failOn={failOn}
                duration={durationText(run.duration_ms)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/** RunRow is one pipeline run, already classified by the fail-on policy. */
function RunRow({
  run,
  failOn,
  duration,
}: {
  run: CIRun
  failOn: CIFailOn
  duration: string
}) {
  const t = useT()
  const failed = runFails(run, failOn)

  return (
    <tr className="align-top hover:bg-hover">
      <td className="py-2 pr-3">{run.display_name}</td>
      <td className="py-2 pl-3 text-xs text-muted">
        {t(`reports.ci-history.trigger.${run.trigger}`)}
      </td>
      <td className="py-2 pl-3 whitespace-nowrap">
        <Badge tone={failed ? 'critical' : 'ok'}>
          {failed
            ? t('reports.ci-history.status.fail')
            : t('reports.ci-history.status.pass')}
        </Badge>
      </td>
      <td className="py-2 pl-3 text-xs whitespace-nowrap text-muted">
        {run.started_at === undefined ? '—' : formatDateTime(run.started_at)}
      </td>
      <td className="py-2 pl-3 text-xs whitespace-nowrap text-muted tabular-nums">
        {duration}
      </td>
      <td className="py-2 pl-3">
        <ReportSeverityChips counts={run.counts} />
      </td>
      <td className="hidden py-2 pl-3 text-xs text-muted sm:table-cell">
        {run.scanners.length === 0 ? (
          <span className="text-faint">—</span>
        ) : (
          run.scanners.map((scanner) => scanner.scanner).join(', ')
        )}
      </td>
    </tr>
  )
}
