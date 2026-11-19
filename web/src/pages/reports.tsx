import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { lazy, Suspense, type ComponentType } from 'react'

import { assetsQuery } from '../api/assets'
import { EmptyState } from '../components/empty-state'
import { BandHeader, BandSummary } from '../components/page-band'
import { ProjectSwitcher } from '../components/project-switcher'
import { buttonVariants } from '../components/ui/button'
import { useT } from '../lib/i18n'
import { reportCatalog, type ReportDefinition, type ReportId } from '../lib/report-catalog'
import type { AssetSearch, ReportSearch } from '../lib/urls'
import { ReportLoading, type ReportPanelProps } from './reports/shared'

/*
 * The panels are split into their own chunks. Only the two chart reports pull
 * recharts in, so a report page downloads what it renders and the card grid
 * stays light (#190).
 */
const LicensesReportPanel = lazy(() =>
  import('./reports/licenses-sbom').then((module) => ({
    default: module.LicensesReportPanel,
  })),
)
const TrendReport = lazy(() =>
  import('./reports/trend').then((module) => ({
    default: module.TrendReport,
  })),
)
const CveInsightsReport = lazy(() =>
  import('./reports/cve-insights').then((module) => ({
    default: module.CveInsightsReport,
  })),
)
const MalwareReportPanel = lazy(() =>
  import('./reports/malware').then((module) => ({
    default: module.MalwareReportPanel,
  })),
)
const RuntimesReportPanel = lazy(() =>
  import('./reports/runtimes').then((module) => ({
    default: module.RuntimesReportPanel,
  })),
)
const CIHistoryReportPanel = lazy(() =>
  import('./reports/ci-history').then((module) => ({
    default: module.CIHistoryReportPanel,
  })),
)
const AuditReportPanel = lazy(() =>
  import('./reports/audit').then((module) => ({
    default: module.AuditReportPanel,
  })),
)
const OwaspTop10Report = lazy(() =>
  import('./reports/owasp-top10').then((module) => ({
    default: module.OwaspTop10Report,
  })),
)
const SlaReportPanel = lazy(() =>
  import('./reports/sla').then((module) => ({
    default: module.SlaReportPanel,
  })),
)

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
 * reportPanels are the reports this build renders, one per catalog id. Every
 * report has a panel, so adding a catalog entry is a compile error until its
 * panel exists too.
 */
const reportPanels: Record<ReportId, ComponentType<ReportPanelProps>> = {
  'licenses-sbom': LicensesReportPanel,
  trend: TrendReport,
  'cve-insights': CveInsightsReport,
  malware: MalwareReportPanel,
  runtimes: RuntimesReportPanel,
  'ci-history': CIHistoryReportPanel,
  audit: AuditReportPanel,
  'owasp-top10': OwaspTop10Report,
  sla: SlaReportPanel,
}

/**
 * ReportPage is one report (#190). The band carries the report's title and the
 * project switcher; the panel below is chosen by the report id.
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

  return (    <>
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
      <Suspense fallback={<ReportLoading />}>
        <Panel search={search} />
      </Suspense>
    </>
  )
}
