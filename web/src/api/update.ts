import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** UpdateStatus is the /api/update payload. */
export type UpdateStatus = components['schemas']['UpdateStatus']

/** UpdateConsent is the stored release-check choice. */
export type UpdateConsent = components['schemas']['UpdateConsent']

export const updateKey = ['update'] as const

/** updateQuery reads the cached release state; the server refreshes at most daily. */
export const updateQuery = queryOptions({
  queryKey: updateKey,
  queryFn: () => api.get<UpdateStatus>('/api/update'),
  // The answer only changes after a daily check, so a few minutes of freshness
  // avoid a request per navigation without hiding a new release for long.
  staleTime: 5 * 60_000,
  // After opting in, the first check runs in the background. Poll until its
  // result (latest) lands, then stop; `latest === undefined` means "not checked
  // yet", while a set latest is either current or newer.
  refetchInterval: (query) => {
    const data = query.state.data
    return data?.consent === 'on' && data.latest === undefined ? 30_000 : false
  },
})

/** useSetUpdateConsent stores the choice and replaces the cached status. */
export function useSetUpdateConsent() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api.put<UpdateStatus>('/api/update/consent', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(updateKey, status)
      // The enable response has no check result yet; refetch so the poll above
      // starts from the server's current state.
      void queryClient.invalidateQueries({ queryKey: updateKey })
    },
  })
}
