import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'

import { runtimesQuery, type RuntimeEntry } from '../../api/reports'
import { EmptyState } from '../../components/empty-state'
import { Badge } from '../../components/ui/badge'
import { useT } from '../../lib/i18n'
import { eolDaysLeft, eolStatus, type EolStatus } from '../../lib/report-runtimes'
import {
  ReportCaption,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  reportCardClass,
  type ReportPanelProps,
} from './shared'

/**
 * RuntimesReportPanel is the Runtimes & frameworks report (#190): every open
 * end-of-life finding grouped by runtime and version, with its end-of-life
 * date, the version that fixes it and the projects running it.
 */
export function RuntimesReportPanel({ search }: ReportPanelProps) {
  const t = useT()
  const report = useQuery(runtimesQuery(search.asset))

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const runtimes = report.data.runtimes
  if (runtimes.length === 0) {
    return (
      <EmptyState
        title={t('reports.runtimes.empty.title')}
        body={t('reports.runtimes.empty.body')}
      />
    )
  }

  return (
    <section className={reportCardClass}>
      <div className="flex flex-col gap-1">
        <ReportPanelHeading
          title={t('reports.runtimes.table.title')}
          aside={t('reports.runtimes.count', { count: runtimes.length })}
        />
        <ReportCaption>{t('reports.runtimes.caption')}</ReportCaption>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[0.8125rem]">
          <thead className="text-xs text-faint">
            <tr>
              <th className="border-b border-border-subtle pb-1.5 font-medium">
                {t('reports.runtimes.column.runtime')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.runtimes.column.version')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.runtimes.column.eol')}
              </th>
              <th className="hidden border-b border-border-subtle pb-1.5 pl-3 font-medium sm:table-cell">
                {t('reports.runtimes.column.fixed')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.runtimes.column.assets')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {runtimes.map((runtime) => (
              <tr
                key={`${runtime.name}:${runtime.version}`}
                className="align-top hover:bg-hover"
              >
                <td className="py-2 pr-3">
                  <span className="block text-[0.875rem]">{runtime.name}</span>
                  {runtime.ecosystem === '' ? null : (
                    <span className="block text-xs text-faint">
                      {runtime.ecosystem}
                    </span>
                  )}
                </td>
                <td className="py-2 pl-3 font-mono whitespace-nowrap">
                  {runtime.version === '' ? (
                    <span className="text-faint">—</span>
                  ) : (
                    runtime.version
                  )}
                </td>
                <td className="py-2 pl-3 whitespace-nowrap">
                  <EolBadge entry={runtime} />
                </td>
                <td className="hidden py-2 pl-3 font-mono whitespace-nowrap sm:table-cell">
                  {runtime.fixed_version === null ? (
                    <span className="text-faint">—</span>
                  ) : (
                    runtime.fixed_version
                  )}
                </td>
                <td className="py-2 pl-3">
                  <span className="text-xs text-faint tabular-nums">
                    {t('reports.runtimes.assets.count', {
                      count: runtime.assets.length,
                    })}
                  </span>
                  <ul className="mt-0.5 flex flex-wrap gap-x-2 gap-y-0.5">
                    {runtime.assets.map((asset) => (
                      <li key={asset.asset_id}>
                        <Link
                          to="/findings/$assetId"
                          params={{ assetId: String(asset.asset_id) }}
                          title={asset.display_name}
                          className="text-[0.8125rem] hover:underline"
                        >
                          {asset.display_name}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/** eolTone maps the end-of-life verdict to the badge tone it is shown with. */
const eolTone: Record<EolStatus, 'critical' | 'medium' | 'ok' | 'neutral'> = {
  past: 'critical',
  soon: 'medium',
  ok: 'ok',
  unknown: 'neutral',
}

/** EolBadge is the end-of-life verdict: past, under 90 days, supported or unknown. */
function EolBadge({ entry }: { entry: RuntimeEntry }) {
  const t = useT()
  const status = eolStatus(entry.eol_date)
  const days = eolDaysLeft(entry.eol_date)

  return (
    <span className="flex flex-col items-start gap-1">
      {entry.eol_date === null ? null : (
        <span className="font-mono text-xs text-muted tabular-nums">
          {entry.eol_date}
        </span>
      )}
      <Badge tone={eolTone[status]}>
        {status === 'soon'
          ? t('reports.runtimes.eol.soon', { count: days ?? 0 })
          : t(`reports.runtimes.eol.${status}`)}
      </Badge>
    </span>
  )
}
