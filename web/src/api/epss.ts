import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** EPSSStatus is the /api/epss payload. */
export type EPSSStatus = components['schemas']['EPSSStatus']

/** EPSSScore is one finding's FIRST.org exploit prediction. */
export type EPSSScore = components['schemas']['EPSSScore']

export const epssKey = ['epss'] as const

/**
 * epssQuery reads the cached feed state; the server refreshes at most daily.
 * After opting in, the first download lands within seconds, so poll until its
 * result (count) or a failure appears and then stop.
 */
export const epssQuery = queryOptions({
  queryKey: epssKey,
  queryFn: () => api.get<EPSSStatus>('/api/epss'),
  staleTime: 60_000,
  refetchInterval: (query) => {
    const data = query.state.data
    return data?.enabled && data.count === undefined && data.error === undefined
      ? 5_000
      : false
  },
})

/** useSetEPSSEnabled stores the opt-in choice and replaces the cached status. */
export function useSetEPSSEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api.put<EPSSStatus>('/api/epss', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(epssKey, status)
      // The enable response carries no scores yet; refetch so the poll above
      // starts from the server's current state.
      void queryClient.invalidateQueries({ queryKey: epssKey })
    },
  })
}
