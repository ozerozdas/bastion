import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** TrivyDBStatus is the /api/trivy-db payload. */
export type TrivyDBStatus = components['schemas']['TrivyDBStatus']

export const trivyDBKey = ['trivy-db'] as const

/**
 * trivyDBQuery reports whether Trivy's vulnerability DB is on disk. A download
 * takes minutes, so poll while one is in flight and stop once it settles.
 */
export const trivyDBQuery = queryOptions({
  queryKey: trivyDBKey,
  queryFn: () => api.get<TrivyDBStatus>('/api/trivy-db'),
  refetchInterval: (query) =>
    query.state.data?.state === 'downloading' ? 2_000 : false,
})

/**
 * useDownloadTrivyDB starts the download. It is idempotent server-side, so the
 * 202 state is authoritative and the poll above carries it to ready or failed.
 */
export function useDownloadTrivyDB() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => api.post<TrivyDBStatus>('/api/trivy-db/download'),
    onSuccess: (status) => {
      queryClient.setQueryData(trivyDBKey, status)
    },
  })
}
