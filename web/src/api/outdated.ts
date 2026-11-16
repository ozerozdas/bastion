import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** OutdatedStatus is the /api/outdated payload. */
export type OutdatedStatus = components['schemas']['OutdatedStatus']

export const outdatedKey = ['outdated'] as const

/**
 * outdatedQuery reads the opt-in outdated-package lookup state. The handler
 * reads the stored setting only, so this never waits on deps.dev.
 */
export const outdatedQuery = queryOptions({
  queryKey: outdatedKey,
  queryFn: () => api.get<OutdatedStatus>('/api/outdated'),
  staleTime: 60_000,
})

/** useSetOutdatedEnabled stores the choice and replaces the cached state. */
export function useSetOutdatedEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api.put<OutdatedStatus>('/api/outdated', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(outdatedKey, status)
    },
  })
}
