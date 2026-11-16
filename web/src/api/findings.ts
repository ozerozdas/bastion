import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Finding is one normalized finding; status is effective (ignored when a decision exists). */
export type Finding = components['schemas']['Finding']
export type FindingType = components['schemas']['FindingType']
export type FindingState = components['schemas']['FindingState']
export type FindingStatus = components['schemas']['FindingStatus']
export type Severity = components['schemas']['Severity']

type FindingList = components['schemas']['FindingList']
type SetFindingStateRequest = components['schemas']['SetFindingStateRequest']
type BulkSetFindingStateRequest = components['schemas']['BulkSetFindingStateRequest']

export type FindingFilter = {
  assetId?: number
  type?: FindingType
  severity?: Severity
  status?: FindingStatus
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

/** latestFindingsQuery reads findings of each asset's latest succeeded scan. */
export function latestFindingsQuery(f: FindingFilter = {}) {
  return queryOptions({
    queryKey: [...findingsKey, 'latest', f],
    queryFn: async () =>
      (await api.get<FindingList>(`/api/findings${filterParams(f)}`)).findings,
  })
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
