import { useQuery } from '@tanstack/react-query'
import { Fragment, useState } from 'react'

import { assetsQuery } from '../../api/assets'
import {
  licensesCsvUrl,
  licensesQuery,
  type LicenseEntry,
} from '../../api/reports'
import { EmptyState } from '../../components/empty-state'
import { Badge } from '../../components/ui/badge'
import { buttonVariants } from '../../components/ui/button'
import { stateLabels } from '../../lib/finding-labels'
import { formatNumber, useT } from '../../lib/i18n'
import {
  ReportCaption,
  ReportChevron,
  ReportError,
  ReportLoading,
  ReportPanelHeading,
  reportCardClass,
  type ReportPanelProps,
} from './shared'

/** itemsShown caps one expanded licence, so a huge inventory stays readable. */
const itemsShown = 50

/** policyTone maps the policy to its badge: denied is critical, allowed ok. */
const policyTone: Record<
  LicenseEntry['policy'],
  'critical' | 'ok' | 'neutral'
> = {
  deny: 'critical',
  allow: 'ok',
  none: 'neutral',
}

/**
 * LicensesReportPanel is the Licenses & SBOM report (#190): the licence
 * inventory grouped by licence, with the effective policy and the packages
 * behind it. The CSV download respects the project scope, and a single project
 * also offers the CycloneDX SBOM of its latest succeeded scan.
 */
export function LicensesReportPanel({ search }: ReportPanelProps) {
  const t = useT()
  const report = useQuery(licensesQuery(search.asset))
  const assets = useQuery({
    ...assetsQuery,
    enabled: search.asset !== undefined,
  })
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const licenses = report.data.licenses
  if (licenses.length === 0) {
    return (
      <EmptyState
        title={t('reports.licenses-sbom.empty.title')}
        body={t('reports.licenses-sbom.empty.body')}
      />
    )
  }

  const asset = assets.data?.find((item) => item.id === search.asset)
  const sbomScanId =
    asset?.last_scan?.status === 'succeeded'
      ? asset.last_scan.scan_id
      : undefined

  function toggle(key: string) {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  return (
    <section className={reportCardClass}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.licenses-sbom.table.title')}
            aside={t('reports.licenses-sbom.count', { count: licenses.length })}
          />
          <ReportCaption>{t('reports.licenses-sbom.caption')}</ReportCaption>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 print-hide">
          <a
            href={licensesCsvUrl(search.asset)}
            download
            className={buttonVariants({ variant: 'outline', size: 'sm' })}
          >
            {t('reports.licenses-sbom.downloadCsv')}
          </a>
          {sbomScanId === undefined ? null : (
            <a
              href={`/api/scans/${String(sbomScanId)}/sbom`}
              download
              title={t('reports.licenses-sbom.sbomTitle')}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              {t('reports.licenses-sbom.downloadSbom')}
            </a>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[0.8125rem]">
          <thead className="text-xs text-faint">
            <tr>
              <th className="border-b border-border-subtle pb-1.5 font-medium">
                {t('reports.licenses-sbom.column.license')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.licenses-sbom.column.policy')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.licenses-sbom.column.packages')}
              </th>
              <th className="border-b border-border-subtle pb-1.5 pl-3 font-medium">
                {t('reports.licenses-sbom.column.assets')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {licenses.map((entry) => {
              // The backend groups by licence and policy, so one licence name
              // can appear more than once; the pair is the row's identity.
              const key = `${entry.license}:${entry.policy}`
              const open = expanded.has(key)
              const shown = entry.items.slice(0, itemsShown)
              return (
                <Fragment key={key}>
                  <tr className="align-top hover:bg-hover">
                    <td className="py-2 pr-3">
                      <button
                        type="button"
                        aria-expanded={open}
                        onClick={() => toggle(key)}
                        className="flex w-full items-center gap-2 rounded px-1 py-0.5 text-left transition-colors hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
                      >
                        <ReportChevron open={open} />
                        <span className="min-w-0 truncate font-mono text-[0.8125rem]">
                          {entry.license}
                        </span>
                        <span className="sr-only">
                          {open
                            ? t('reports.licenses-sbom.hide')
                            : t('reports.licenses-sbom.show')}
                        </span>
                      </button>
                    </td>
                    <td className="py-2 pl-3 whitespace-nowrap">
                      <Badge tone={policyTone[entry.policy]}>
                        {t(
                          `reports.licenses-sbom.policy.${entry.policy}`,
                        )}
                      </Badge>
                    </td>
                    <td className="py-2 pl-3 tabular-nums">
                      {formatNumber(entry.packages)}
                      {entry.ignored_packages > 0 ? (
                        <span className="block text-xs text-faint">
                          {t('reports.licenses-sbom.ignored', {
                            count: entry.ignored_packages,
                          })}
                        </span>
                      ) : null}
                    </td>
                    <td className="py-2 pl-3 tabular-nums">
                      {formatNumber(entry.assets)}
                    </td>
                  </tr>
                  {open ? (
                    <tr>
                      <td colSpan={4} className="pb-3">
                        <ul
                          aria-label={t('reports.licenses-sbom.items.aria', {
                            license: entry.license,
                          })}
                          className="divide-y divide-border-subtle border-l border-border-subtle pl-3 sm:ml-5"
                        >
                          {shown.map((item) => (
                            <li
                              key={`${String(item.asset_id)}:${item.package_name}:${item.package_version}`}
                              className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 py-1.5"
                            >
                              <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                                <span className="font-mono text-[0.8125rem]">
                                  {item.package_name}
                                  {item.package_version === ''
                                    ? ''
                                    : `@${item.package_version}`}
                                </span>
                                {item.ecosystem === '' ? null : (
                                  <span className="text-xs text-faint">
                                    {item.ecosystem}
                                  </span>
                                )}
                                {item.state === null ? null : (
                                  <Badge tone="neutral">
                                    {t(stateLabels[item.state])}
                                  </Badge>
                                )}
                              </span>
                              <span className="text-xs text-muted">
                                {item.display_name}
                              </span>
                            </li>
                          ))}
                        </ul>
                        {entry.items.length > shown.length ? (
                          <p className="pl-3 pt-1 text-xs text-muted sm:ml-5">
                            {t('reports.licenses-sbom.truncated', {
                              shown: shown.length,
                              total: entry.items.length,
                            })}
                          </p>
                        ) : null}
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
