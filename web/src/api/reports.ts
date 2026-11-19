import {
  queryOptions,
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Dashboard is the aggregates payload of GET /api/reports/dashboard (§7.1). */
export type Dashboard = components['schemas']['Dashboard']

/** SeverityTotals is findings per severity (open ones on assets, recorded ones on scans). */
export type SeverityTotals = components['schemas']['SeverityTotals']

/** TypeTotals is open findings per finding type. */
export type TypeTotals = components['schemas']['TypeTotals']

/** AssetRisk is one row of the riskiest-assets list. */
export type AssetRisk = components['schemas']['AssetRisk']

/** AssetTrend is one asset's critical+high series, oldest scan first. */
export type AssetTrend = components['schemas']['AssetTrend']

/** LastScan is the newest scan of one asset, whatever its status. */
export type LastScan = components['schemas']['LastScan']

/**
 * dashboardQuery reads every dashboard number in one request. The payload is a
 * point-in-time aggregate, so a fresh load after a scan is the way to refresh.
 */
export const dashboardQuery = queryOptions({
  queryKey: ['dashboard'],
  queryFn: () => api.get<Dashboard>('/api/reports/dashboard'),
})

/** openFindingTotal sums the severity totals into one count of open findings. */
export function openFindingTotal(totals: SeverityTotals): number {
  return (
    totals.critical + totals.high + totals.medium + totals.low + totals.unknown
  )
}

/** ReportTrend is one asset's daily open counts by severity (#190). */
export type ReportTrend = components['schemas']['ReportTrend']

/** ReportTrendSeries is one asset's points, oldest first. */
export type ReportTrendSeries = components['schemas']['ReportTrendSeries']

/** ReportTrendPoint is one scanned day's open counts. */
export type ReportTrendPoint = components['schemas']['ReportTrendPoint']

/** CVEInsights is one advisory's affected assets and its EPSS prediction. */
export type CVEInsights = components['schemas']['CVEInsights']

/** CVEInsightAsset is one project affected by the looked-up advisory. */
export type CVEInsightAsset = components['schemas']['CVEInsightAsset']

/** EPSSScore is FIRST.org's score and percentile for an advisory. */
export type EPSSScore = components['schemas']['EPSSScore']

/** OWASPTop10 is the ten 2021 categories, then unmapped. */
export type OWASPTop10 = components['schemas']['OWASPTop10']

/** OWASPCategory is one category and its open findings. */
export type OWASPCategory = components['schemas']['OWASPCategory']

/** MalwareReport is the latest open malware findings. */
export type MalwareReport = components['schemas']['MalwareReport']

/** RuntimesReport is the end-of-life runtimes and the assets running them. */
export type RuntimesReport = components['schemas']['RuntimesReport']

/** RuntimeEntry is one runtime name and version. */
export type RuntimeEntry = components['schemas']['RuntimeEntry']

/** RuntimeAsset is one project running a runtime. */
export type RuntimeAsset = components['schemas']['RuntimeAsset']

/** LicensesReport is the licence inventory with its effective policy. */
export type LicensesReport = components['schemas']['LicensesReport']

/** LicenseEntry is one licence and the policy that applies to it. */
export type LicenseEntry = components['schemas']['LicenseEntry']

/** LicenseItem is one finding behind a licence entry. */
export type LicenseItem = components['schemas']['LicenseItem']

/** AuditReport is the audit pack: summary, findings and fix plan. */
export type AuditReport = components['schemas']['AuditReport']

/** AuditAsset is the asset an audit pack is for, or null for the fleet. */
export type AuditAsset = components['schemas']['AuditAsset']

/** AuditSummary counts the audit pack's findings per severity. */
export type AuditSummary = components['schemas']['AuditSummary']

/** CIHistoryReport is the CLI and API scan runs, newest first. */
export type CIHistoryReport = components['schemas']['CIHistoryReport']

/** CIRun is one scan a pipeline started. */
export type CIRun = components['schemas']['CIRun']

/** SLAReport is the overdue findings and the fix statistics of the window. */
export type SLAReport = components['schemas']['SLAReport']

/** SLAOverdueFinding is one open finding past its severity's threshold. */
export type SLAOverdueFinding = components['schemas']['SLAOverdueFinding']

/** SLAThresholds is the days a finding of each severity may stay open. */
export type SLAThresholds = components['schemas']['SLAThresholds']

/** reportsKey prefixes every report query, so one invalidation refreshes them. */
export const reportsKey = ['reports'] as const

/** ReportScope is the shared scope of most reports: one project or the fleet. */
export type ReportScope = {
  assetId?: number
  /** Length of the window in days, where the report has one. */
  days?: number
}

/** reportParams renders report scope as a query string ("" when unscoped). */
function reportParams(f: ReportScope): string {
  const params = new URLSearchParams()
  if (f.assetId !== undefined) params.set('asset_id', String(f.assetId))
  if (f.days !== undefined) params.set('days', String(f.days))
  const query = params.toString()
  return query ? `?${query}` : ''
}

/** trendQuery reads the per-asset daily open counts of the window. */
export function trendQuery(f: ReportScope = {}) {
  return queryOptions({
    queryKey: [...reportsKey, 'trend', f],
    queryFn: () => api.get<ReportTrend>(`/api/reports/trend${reportParams(f)}`),
  })
}

/**
 * cveInsightsQuery looks one advisory up. The API needs `cve`, so the query
 * stays disabled until the input carries something to search for.
 */
export function cveInsightsQuery(cve: string, assetId?: number) {
  const params = new URLSearchParams({ cve })
  if (assetId !== undefined) params.set('asset_id', String(assetId))
  return queryOptions({
    queryKey: [...reportsKey, 'cve-insights', cve, assetId ?? null],
    queryFn: () =>
      api.get<CVEInsights>(`/api/reports/cve-insights?${params.toString()}`),
    enabled: cve !== '',
  })
}

/** owaspTop10Query reads the latest open findings grouped by OWASP category. */
export function owaspTop10Query(assetId?: number) {
  return queryOptions({
    queryKey: [...reportsKey, 'owasp-top10', assetId ?? null],
    queryFn: () =>
      api.get<OWASPTop10>(
        `/api/reports/owasp-top10${reportParams({ assetId })}`,
      ),
  })
}

/** malwareQuery reads the latest open malware findings. */
export function malwareQuery(assetId?: number) {
  return queryOptions({
    queryKey: [...reportsKey, 'malware', assetId ?? null],
    queryFn: () =>
      api.get<MalwareReport>(`/api/reports/malware${reportParams({ assetId })}`),
  })
}

/** runtimesQuery reads the end-of-life runtimes and their assets. */
export function runtimesQuery(assetId?: number) {
  return queryOptions({
    queryKey: [...reportsKey, 'runtimes', assetId ?? null],
    queryFn: () =>
      api.get<RuntimesReport>(
        `/api/reports/runtimes${reportParams({ assetId })}`,
      ),
  })
}

/** licensesQuery reads the licence inventory with its effective policy. */
export function licensesQuery(assetId?: number) {
  return queryOptions({
    queryKey: [...reportsKey, 'licenses', assetId ?? null],
    queryFn: () =>
      api.get<LicensesReport>(
        `/api/reports/licenses${reportParams({ assetId })}`,
      ),
  })
}

/** licensesCsvUrl is the download URL of the same inventory, as a CSV attachment. */
export function licensesCsvUrl(assetId?: number): string {
  return `/api/reports/licenses.csv${reportParams({ assetId })}`
}

/** auditQuery reads the audit pack of one asset, or of the fleet. */
export function auditQuery(assetId?: number) {
  return queryOptions({
    queryKey: [...reportsKey, 'audit', assetId ?? null],
    queryFn: () =>
      api.get<AuditReport>(`/api/reports/audit${reportParams({ assetId })}`),
  })
}

/** CITrigger is who started a scan: the app, the CLI or the API. */
export type CITrigger = CIRun['trigger']

/** CIHistoryScope is the run history's scope, page size and trigger filter. */
export type CIHistoryScope = {
  assetId?: number
  /** Maximum number of runs, newest first; the API defaults to 50. */
  limit?: number
  /** Only runs started from this surface; absent means every trigger. */
  trigger?: CITrigger
}

/** ciHistoryQuery reads the scans pipelines started, newest first. */
export function ciHistoryQuery(f: CIHistoryScope = {}) {
  const params = new URLSearchParams()
  if (f.assetId !== undefined) params.set('asset_id', String(f.assetId))
  if (f.limit !== undefined) params.set('limit', String(f.limit))
  if (f.trigger !== undefined) params.set('trigger', f.trigger)
  const query = params.toString()
  return queryOptions({
    queryKey: [...reportsKey, 'ci-history', f],
    queryFn: () =>
      api.get<CIHistoryReport>(
        `/api/reports/ci-history${query ? `?${query}` : ''}`,
      ),
  })
}

/** slaQuery reads the overdue findings and fix statistics of the window. */
export function slaQuery(f: ReportScope = {}) {
  return queryOptions({
    queryKey: [...reportsKey, 'sla', f],
    queryFn: () => api.get<SLAReport>(`/api/reports/sla${reportParams(f)}`),
  })
}

/** slaSettingsKey is the SLA thresholds' cache key. */
export const slaSettingsKey = ['settings', 'sla'] as const

/** slaSettingsQuery reads the stored SLA thresholds. */
export const slaSettingsQuery = queryOptions({
  queryKey: slaSettingsKey,
  queryFn: () => api.get<SLAThresholds>('/api/settings/sla'),
  staleTime: 30_000,
})

/** useSetSlaSettings replaces the thresholds and caches what the server stored. */
export function useSetSlaSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (thresholds: SLAThresholds) =>
      api.put<SLAThresholds>('/api/settings/sla', thresholds),
    onSuccess: (thresholds) => {
      queryClient.setQueryData(slaSettingsKey, thresholds)
      void queryClient.invalidateQueries({ queryKey: [...reportsKey, 'sla'] })
    },
  })
}
