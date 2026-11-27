import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** OSVStatus is the /api/osv payload. */
export type OSVStatus = components['schemas']['OSVStatus']

export const osvKey = ['osv'] as const

/** osvQuery reads the stored opt-in; it never reaches api.osv.dev. */
export const osvQuery = queryOptions({
  queryKey: osvKey,
  queryFn: () => api.get<OSVStatus>('/api/osv'),
  staleTime: 60_000,
})

/** useSetOSVEnabled stores the choice and replaces the cached state. */
export function useSetOSVEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) => api.put<OSVStatus>('/api/osv', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(osvKey, status)
    },
  })
}
