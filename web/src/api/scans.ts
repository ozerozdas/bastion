import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { assetsKey } from './assets'
import { api } from './client'
import type { components } from './schema'

/** Scan is one scan of one asset; scanner_runs is set on the detail endpoint. */
export type Scan = components['schemas']['Scan']

/** ScanDiff is the findings new, fixed and persisting between two scans (#17). */
export type ScanDiff = components['schemas']['ScanDiff']

type ScanList = components['schemas']['ScanList']
type ScanQueueResult = components['schemas']['ScanQueueResult']

export const scansKey = ['scans'] as const

/** scansQuery lists scans newest first, optionally for one asset. */
export function scansQuery(assetId?: number, limit = 50) {
  const params = new URLSearchParams({ limit: String(limit) })
  if (assetId !== undefined) params.set('asset_id', String(assetId))
  return queryOptions({
    queryKey: [...scansKey, 'list', assetId ?? null, limit],
    queryFn: async () => (await api.get<ScanList>(`/api/scans?${params}`)).scans,
  })
}

/** scanQuery loads one scan with its scanner runs. */
export function scanQuery(id: number) {
  return queryOptions({
    queryKey: [...scansKey, 'detail', id],
    queryFn: () => api.get<Scan>(`/api/scans/${id}`),
  })
}

/** scanDiffQuery compares a scan with another, or with its previous succeeded scan. */
export function scanDiffQuery(id: number, against?: number) {
  const params = new URLSearchParams()
  if (against !== undefined) params.set('against', String(against))
  const query = params.toString()
  return queryOptions({
    queryKey: [...scansKey, 'diff', id, against ?? null],
    queryFn: () =>
      api.get<ScanDiff>(`/api/scans/${id}/diff${query ? `?${query}` : ''}`),
  })
}

function invalidateScans(queryClient: ReturnType<typeof useQueryClient>) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: scansKey }),
    queryClient.invalidateQueries({ queryKey: assetsKey }),
  ])
}

/** useStartScans queues one scan per asset. */
export function useStartScans() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (assetIds: number[]) =>
      api.post<ScanQueueResult>('/api/scans', { asset_ids: assetIds }),
    onSuccess: () => invalidateScans(queryClient),
  })
}

/** useCancelScan cancels a queued or running scan (409 when already finished). */
export function useCancelScan() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.post<Scan>(`/api/scans/${id}/cancel`),
    onSuccess: () => invalidateScans(queryClient),
  })
}
