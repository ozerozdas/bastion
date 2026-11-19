import { useQuery } from '@tanstack/react-query'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'

import { auditQuery } from '../../api/reports'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { severityLabel, severityTone } from '../../lib/finding-labels'
import { formatNumber, useT } from '../../lib/i18n'
import { formatDateTime } from '../../lib/time'
import {
  ReportCaption,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  ReportSeverityChips,
  ReportStat,
  reportCardClass,
  type ReportPanelProps,
} from './shared'

/** AuditSeverity is the severities the summary and the pie show. */
type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

/** severityOrder is the audit summary's reading order, worst first. */
const severityOrder: AuditSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
]

/** severityColors paint the pie from the theme tokens, in print and on screen. */
const severityColors: Record<AuditSeverity, string> = {
  critical: 'var(--b-critical)',
  high: 'var(--b-high)',
  medium: 'var(--b-medium)',
  low: 'var(--b-low)',
  unknown: 'var(--b-border-strong)',
}

/**
 * AuditReportPanel is the printable Security audit (#190): a header with the
 * scope and generation time, the severity summary, the fix plan and every
 * finding with its fix. The print button hands the page to the browser's
 * PDF dialog; the print stylesheet drops the app frame around it.
 */
export function AuditReportPanel({ search }: ReportPanelProps) {
  const t = useT()
  const report = useQuery(auditQuery(search.asset))

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const data = report.data
  const summary = data.summary
  const scope = data.asset?.display_name ?? t('reports.audit.header.all')
  const chartData = severityOrder
    .map((severity) => ({
      key: severity,
      label: severityLabel(severity),
      count: summary[severity],
      color: severityColors[severity],
    }))
    .filter((entry) => entry.count > 0)

  return (
    <section className="print-report flex flex-col gap-4">
      <header className="flex flex-wrap items-start justify-between gap-3 rounded-card border border-border-subtle bg-surface p-4 sm:p-5 print-avoid">
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold tracking-[-0.01em]">
            {t('reports.audit.header.title')}
          </h2>
          <p className="text-[0.8125rem] text-muted">{scope}</p>
          <p className="text-xs text-faint">
            {t('reports.audit.header.generated', {
              date: formatDateTime(data.generated_at),
            })}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          className="print-hide"
          onClick={() => window.print()}
        >
          {t('reports.audit.print')}
        </Button>
      </header>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5 print-avoid">
        {severityOrder.map((severity) => (
          <ReportStat
            key={severity}
            label={severityLabel(severity)}
            value={formatNumber(summary[severity])}
          />
        ))}
      </div>

      <section className={reportCardClass}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.audit.chart.title')}
            aside={t('reports.audit.summary.total', { count: summary.total })}
          />
          <ReportCaption>{t('reports.audit.chart.caption')}</ReportCaption>
        </div>
        {chartData.length === 0 ? (
          <p className="py-2 text-xs text-muted">
            {t('reports.audit.chart.empty')}
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-4">
            <div
              role="img"
              aria-label={t('reports.audit.chart.aria')}
              className="size-40 shrink-0"
            >
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="count"
                    nameKey="label"
                    innerRadius={40}
                    outerRadius={70}
                    paddingAngle={2}
                    isAnimationActive={false}
                  >
                    {chartData.map((entry) => (
                      <Cell key={entry.key} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: 'var(--b-surface)',
                      border: '1px solid var(--b-border-subtle)',
                      borderRadius: 8,
                      color: 'var(--b-fg)',
                      fontSize: 12,
                      padding: '6px 10px',
                    }}
                    itemStyle={{ color: 'var(--b-fg)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <ul className="flex flex-col gap-1.5">
              {chartData.map((entry) => (
                <li key={entry.key} className="flex items-center gap-2 text-xs">
                  <span
                    aria-hidden="true"
                    className="size-2.5 rounded-full"
                    style={{ background: entry.color }}
                  />
                  <Badge tone={severityTone[entry.key]}>
                    {severityLabel(entry.key)}
                  </Badge>
                  <span className="font-semibold tabular-nums">
                    {formatNumber(entry.count)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className={reportCardClass}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading title={t('reports.audit.fixPlan.title')} />
          <ReportCaption>{t('reports.audit.fixPlan.caption')}</ReportCaption>
        </div>
        {data.fix_plan.steps.length === 0 ? (
          <p className="py-2 text-xs text-muted">
            {t('reports.audit.fixPlan.empty')}
          </p>
        ) : (
          <ol className="flex flex-col divide-y divide-border-subtle">
            {data.fix_plan.steps.map((step) => (
              <li
                key={`${step.ecosystem}:${step.package}`}
                className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 py-2 print-avoid"
              >
                <span className="flex min-w-0 flex-col">
                  <span className="text-[0.8125rem]">
                    {t('reports.audit.fixPlan.step', {
                      package: step.package,
                      version: step.target_version,
                    })}
                  </span>
                  <span className="text-xs text-faint">
                    {t('reports.audit.fixPlan.installed', {
                      versions:
                        step.installed_versions.length === 0
                          ? '—'
                          : step.installed_versions.join(', '),
                    })}
                    {step.approximate
                      ? ` · ${t('reports.audit.fixPlan.approximate')}`
                      : ''}
                  </span>
                </span>
                <span className="flex items-center gap-2">
                  <ReportSeverityChips counts={step.severity_counts} />
                  <span className="text-xs text-faint tabular-nums">
                    {t('reports.audit.fixPlan.count', {
                      count: step.finding_count,
                    })}
                  </span>
                </span>
              </li>
            ))}
          </ol>
        )}
        {data.fix_plan.no_fix.length === 0 ? null : (
          <p className="border-t border-border-subtle pt-2 text-xs text-muted">
            {t('reports.audit.fixPlan.noFix', {
              count: data.fix_plan.no_fix.length,
            })}
          </p>
        )}
      </section>

      <section className={reportCardClass}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.audit.findings.title')}
            aside={t('reports.audit.findings.count', {
              count: data.findings.length,
            })}
          />
          <ReportCaption>{t('reports.audit.findings.caption')}</ReportCaption>
        </div>

        {data.findings.length === 0 ? (
          <div className="flex flex-col gap-1 py-2">
            <p className="text-[0.875rem] font-medium">
              {t('reports.audit.empty.title')}
            </p>
            <p className="text-xs text-muted">
              {t('reports.audit.empty.body')}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[0.8125rem]">
                <thead className="text-xs text-faint">
                  <tr>
                    <th className="border-b border-border-subtle pb-1.5 font-medium">
                      {t('reports.audit.column.severity')}
                    </th>
                    <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                      {t('reports.audit.column.finding')}
                    </th>
                    <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                      {t('reports.audit.column.package')}
                    </th>
                    <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                      {t('reports.audit.column.fixed')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {data.findings.map((finding) => (
                    <tr
                      key={`${String(finding.asset_id)}:${finding.fingerprint}`}
                      className="align-top print-avoid"
                    >
                      <td className="py-1.5 pr-3 whitespace-nowrap">
                        <Badge tone={severityTone[finding.severity]}>
                          {severityLabel(finding.severity)}
                        </Badge>
                      </td>
                      <td className="py-1.5 pl-3">
                        <span className="block">{finding.title}</span>
                        {finding.rule_id === undefined ? null : (
                          <span className="block font-mono text-[0.6875rem] text-faint">
                            {finding.rule_id}
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 pl-3 font-mono text-xs">
                        {finding.package_name === undefined ? (
                          <span className="text-faint">—</span>
                        ) : (
                          <>
                            {finding.package_name}
                            {finding.package_version === undefined
                              ? ''
                              : `@${finding.package_version}`}
                          </>
                        )}
                      </td>
                      <td className="py-1.5 pl-3 font-mono text-xs whitespace-nowrap">
                        {finding.fixed_version === undefined ? (
                          <span className="text-faint">—</span>
                        ) : (
                          finding.fixed_version
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {data.truncated ? (
              <p className="border-t border-border-subtle pt-2 text-xs text-muted">
                {t('reports.audit.truncated', {
                  shown: data.findings.length,
                  total: summary.total,
                })}
              </p>
            ) : null}
          </>
        )}
      </section>
    </section>
  )
}
