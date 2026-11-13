import { queryOptions } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Dashboard is the aggregates payload of GET /api/reports/dashboard (§7.1). */
export type Dashboard = components['schemas']['Dashboard']

/** SeverityTotals is open findings per severity. */
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
