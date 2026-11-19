import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import type { ComponentType } from 'react'

import { assetsQuery } from '../api/assets'
import { EmptyState } from '../components/empty-state'
import { BandHeader, BandSummary } from '../components/page-band'
import { ProjectSwitcher } from '../components/project-switcher'
import { buttonVariants } from '../components/ui/button'
import { useT } from '../lib/i18n'
import { reportCatalog, type ReportDefinition, type ReportId } from '../lib/report-catalog'
import type { AssetSearch, ReportSearch } from '../lib/urls'
import { CveInsightsReport } from './reports/cve-insights'
import { MalwareReportPanel } from './reports/malware'
import { OwaspTop10Report } from './reports/owasp-top10'
import { RuntimesReportPanel } from './reports/runtimes'
import type { ReportPanelProps } from './reports/shared'
import { TrendReport } from './reports/trend'

/** assetSearch keeps ?asset=<id> on a link; absent is every project. */
function assetSearch(asset: number | undefined): AssetSearch {
  return asset === undefined ? {} : { asset }
}

/**
 * ReportsPage is the Reports card grid (#190): one card per report, each
 * opening its own page. The project switcher scopes every card's report.
 */
export function ReportsPage() {
  const t = useT()
  const search = useSearch({ from: '/reports' })
  const navigate = useNavigate()
  const assets = useQuery(assetsQuery)
  const current = assets.data?.find((asset) => asset.id === search.asset)

  return (
    <>
      <BandHeader>
        <BandSummary
          title={t('nav.reports')}
          subtitle={t('nav.reports.subtitle')}
          actions={
            <ProjectSwitcher
              assets={assets.data ?? []}
              current={current}
              heading="none"
              onChange={(assetId) =>
                void navigate({
                  to: '/reports',
                  search: assetSearch(assetId ?? undefined),
                })
              }
            />
          }
        />
      </BandHeader>
      <ul
        aria-label={t('reports.list.aria')}
        className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3"
      >
        {reportCatalog.map((report) => (
          <ReportCard key={report.id} report={report} asset={search.asset} />
        ))}
      </ul>
    </>
  )
}

/** ReportCard is one report's card: its icon, title and one-line description. */
function ReportCard({
  report,
  asset,
}: {
  report: ReportDefinition
  asset: number | undefined
}) {
  const t = useT()
  const Icon = report.icon
  return (
    <li>
      <Link
        to="/reports/$reportId"
        params={{ reportId: report.id }}
        search={assetSearch(asset)}
        className="flex h-full flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4 transition-colors hover:border-accent hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
      >
        <span className="flex items-center gap-2 text-[0.9375rem] font-semibold">
          <Icon className="size-4 shrink-0 text-muted" />
          {t(report.titleKey)}
        </span>
        <span className="text-xs text-muted">{t(report.descriptionKey)}</span>
      </Link>
    </li>
  )
}

/**
 * reportPanels are the reports this build renders. An id missing here keeps the
 * Coming soon state, so the catalog can ship ahead of its panels.
 */
const reportPanels: Partial<
  Record<ReportId, ComponentType<ReportPanelProps>>
> = {
  trend: TrendReport,
  'cve-insights': CveInsightsReport,
  'owasp-top10': OwaspTop10Report,
  malware: MalwareReportPanel,
  runtimes: RuntimesReportPanel,
}

/**
 * ReportPage is one report (#190). The band carries the report's title and the
 * project switcher; the panel below is chosen by the report id, and a report
 * without a panel yet explains that it is on the way.
 */
export function ReportPage() {
  const t = useT()
  const { reportId } = useParams({ from: '/reports/$reportId' })
  const search = useSearch({ from: '/reports/$reportId' })
  const navigate = useNavigate()
  const assets = useQuery(assetsQuery)
  const report = reportCatalog.find((item) => item.id === reportId)
  const current = assets.data?.find((asset) => asset.id === search.asset)

  if (report === undefined) {
    return (
      <>
        <BandHeader>
          <BandSummary title={t('nav.reports')} />
        </BandHeader>
        <EmptyState
          title={t('reports.notFound.title')}
          body={t('reports.notFound.body')}
        >
          <Link to="/reports" className={buttonVariants()}>
            {t('nav.reports')}
          </Link>
        </EmptyState>
      </>
    )
  }

  const Panel = reportPanels[report.id]

  return (
    <>
      <BandHeader>
        <BandSummary
          title={t(report.titleKey)}
          subtitle={t(report.descriptionKey)}
          actions={
            <ProjectSwitcher
              assets={assets.data ?? []}
              current={current}
              heading="none"
              onChange={(assetId) => {
                const nextSearch: ReportSearch = { ...search }
                if (assetId === null) delete nextSearch.asset
                else nextSearch.asset = assetId
                void navigate({
                  to: '/reports/$reportId',
                  params: { reportId: report.id },
                  search: nextSearch,
                })
              }}
            />
          }
        />
      </BandHeader>
      {Panel === undefined ? (
        <EmptyState
          title={t('reports.comingSoon.title')}
          body={t('reports.comingSoon.body')}
        />
      ) : (
        <Panel search={search} />
      )}
    </>
  )
}
