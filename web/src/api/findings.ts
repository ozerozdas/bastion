import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import type { FindingsSort, SortOrder } from '../lib/urls'
import { api } from './client'
import type { components } from './schema'

/** Finding is one normalized finding; status is effective (ignored when a decision exists). */
export type Finding = components['schemas']['Finding']
export type FindingType = components['schemas']['FindingType']
export type FindingState = components['schemas']['FindingState']
export type FindingStatus = components['schemas']['FindingStatus']
export type Severity = components['schemas']['Severity']
/** FindingGroup is one rule and type folded across projects; the API builds it. */
export type FindingGroup = components['schemas']['FindingGroup']

export type FindingList = components['schemas']['FindingList']
type SetFindingStateRequest = components['schemas']['SetFindingStateRequest']
type BulkSetFindingStateRequest = components['schemas']['BulkSetFindingStateRequest']

export type FindingFilter = {
  assetId?: number
  type?: FindingType
  severity?: Severity
  status?: FindingStatus
}

/** FindingsQuery is the filter plus the view and the page window. */
export type FindingsQuery = FindingFilter & {
  /** single is one row per finding; grouped folds one row per rule and type. */
  view?: 'single' | 'grouped'
  limit?: number
  offset?: number
  /** A whitelisted column the server orders the page by. */
  sort?: FindingsSort
  /** Direction of sort; ascending when absent. */
  order?: SortOrder
}

export const findingsKey = ['findings'] as const

/** filterParams renders the finding filters as a query string ("" when none). */
export function filterParams(f: FindingFilter): string {
  const params = new URLSearchParams()
  if (f.assetId !== undefined) params.set('asset_id', String(f.assetId))
  if (f.type) params.set('type', f.type)
  if (f.severity) params.set('severity', f.severity)
  if (f.status) params.set('status', f.status)
  const query = params.toString()
  return query ? `?${query}` : ''
}

/** findingsParams renders the filters, view and page window as a query string. */
function findingsParams(f: FindingsQuery): string {
  const params = new URLSearchParams(filterParams(f))
  if (f.view) params.set('view', f.view)
  if (f.sort) params.set('sort', f.sort)
  if (f.order) params.set('order', f.order)
  if (f.limit !== undefined) params.set('limit', String(f.limit))
  if (f.offset !== undefined) params.set('offset', String(f.offset))
  return `?${params.toString()}`
}

/** latestFindingsQuery reads one page of each asset's latest findings. */
export function latestFindingsQuery(f: FindingsQuery = {}) {
  return queryOptions({
    queryKey: [...findingsKey, 'latest', f],
    queryFn: async () => api.get<FindingList>(`/api/findings${findingsParams(f)}`),
  })
}

/** allFindingsQuery reads every single-view finding of the filter, page by page. */
export function allFindingsQuery(f: FindingFilter = {}) {
  return queryOptions({
    queryKey: [...findingsKey, 'all', f],
    queryFn: async () => {
      const findings: FindingList['findings'] = []
      for (let offset = 0; ; offset += 500) {
        const page = await api.get<FindingList>(
          `/api/findings${findingsParams({ ...f, view: 'single', limit: 500, offset })}`,
        )
        findings.push(...page.findings)
        if (page.findings.length === 0 || findings.length >= page.total) return findings
      }
    },
  })
}

/** FindingsExportFormat is the download format of the findings export. */
export type FindingsExportFormat = 'csv' | 'xlsx' | 'json'

/** FindingsExportView is one row per rule (grouped) or one row per finding. */
export type FindingsExportView = 'grouped' | 'single'

/**
 * exportFindingsUrl is the download URL for the current filters and view. It
 * carries the same filter params as the list, so the file matches what the page
 * shows; a plain link downloads it with the session cookie.
 */
export function exportFindingsUrl(
  f: FindingFilter & { format: FindingsExportFormat; view: FindingsExportView },
): string {
  const params = new URLSearchParams()
  if (f.assetId !== undefined) params.set('asset_id', String(f.assetId))
  if (f.type) params.set('type', f.type)
  if (f.severity) params.set('severity', f.severity)
  if (f.status) params.set('status', f.status)
  params.set('format', f.format)
  params.set('view', f.view)
  return `/api/findings/export?${params.toString()}`
}

/** scanFindingsQuery reads the findings of one scan (asset_id is ignored). */
export function scanFindingsQuery(scanId: number, f: Omit<FindingFilter, 'assetId'> = {}) {
  return queryOptions({
    queryKey: [...findingsKey, 'scan', scanId, f],
    queryFn: async () =>
      (await api.get<FindingList>(`/api/scans/${scanId}/findings${filterParams(f)}`))
        .findings,
  })
}

/** useSetFindingState records a decision (reason required); it applies to later scans too. */
export function useSetFindingState() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ fingerprint, ...body }: SetFindingStateRequest & { fingerprint: string }) =>
      api.post<void>(`/api/findings/${encodeURIComponent(fingerprint)}/state`, body),
    onSuccess: () => queryClient.invalidateQueries(),
  })
}

/** FindingRef names one finding's decision key: a fingerprint only exists within its asset. */
export type FindingRef = {
  assetId: number
  fingerprint: string
}

/** FindingStateBatch is one asset's share of a selection: the unit of a bulk request. */
export type FindingStateBatch = {
  assetId: number
  fingerprints: string[]
}

/**
 * findingStateBatches groups a selection by asset, because a decision is keyed
 * on (asset_id, fingerprint) and the bulk endpoint takes one asset per request.
 */
export function findingStateBatches(findings: FindingRef[]): FindingStateBatch[] {
  const byAsset = new Map<number, string[]>()
  for (const { assetId, fingerprint } of findings) {
    const fingerprints = byAsset.get(assetId)
    if (fingerprints) fingerprints.push(fingerprint)
    else byAsset.set(assetId, [fingerprint])
  }
  return [...byAsset].map(([assetId, fingerprints]) => ({ assetId, fingerprints }))
}

/**
 * useBulkFindingState records one decision for many findings, across projects,
 * or reopens them all when state is omitted. A selection is grouped by asset,
 * so one asset is one request: a decision is all-or-nothing per asset, and
 * assets before a failed one keep their new state.
 */
export function useBulkFindingState() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      findings,
      decision,
    }: {
      findings: FindingRef[]
      decision?: Omit<SetFindingStateRequest, 'asset_id'>
    }) => {
      for (const { assetId, fingerprints } of findingStateBatches(findings)) {
        if (decision) {
          const body: BulkSetFindingStateRequest = {
            asset_id: assetId,
            fingerprints,
            ...decision,
          }
          await api.post<void>('/api/findings/state', body)
          continue
        }
        // Reopening has no batch endpoint: a decision is cleared per finding.
        for (const fingerprint of fingerprints) {
          await api.remove<void>(
            `/api/findings/${encodeURIComponent(fingerprint)}/state?asset_id=${assetId}`,
          )
        }
      }
    },
    onSettled: () => queryClient.invalidateQueries(),
  })
}

/** useClearFindingState reopens a finding by deleting its decision. */
export function useClearFindingState() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ fingerprint, assetId }: { fingerprint: string; assetId: number }) =>
      api.remove<void>(
        `/api/findings/${encodeURIComponent(fingerprint)}/state?asset_id=${assetId}`,
      ),
    onSuccess: () => queryClient.invalidateQueries(),
  })
}
