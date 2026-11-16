import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** ReachabilityStatus is the /api/reachability payload. */
export type ReachabilityStatus = components['schemas']['ReachabilityStatus']

export const reachabilityKey = ['reachability'] as const

/**
 * reachabilityQuery reads the opt-in Go reachability state. The probe is a PATH
 * lookup on the server, so this never waits on a process.
 */
export const reachabilityQuery = queryOptions({
  queryKey: reachabilityKey,
  queryFn: () => api.get<ReachabilityStatus>('/api/reachability'),
  staleTime: 60_000,
})

/** useSetReachabilityEnabled stores the choice and replaces the cached state. */
export function useSetReachabilityEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api.put<ReachabilityStatus>('/api/reachability', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(reachabilityKey, status)
    },
  })
}
