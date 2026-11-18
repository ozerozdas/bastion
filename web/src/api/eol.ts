import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** EOLStatus is the /api/eol payload. */
export type EOLStatus = components['schemas']['EOLStatus']

export const eolKey = ['eol'] as const

/** eolQuery reads the stored opt-in; it never waits on endoflife.date. */
export const eolQuery = queryOptions({
  queryKey: eolKey,
  queryFn: () => api.get<EOLStatus>('/api/eol'),
  staleTime: 60_000,
})

/** useSetEOLEnabled stores the choice and replaces the cached state. */
export function useSetEOLEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api.put<EOLStatus>('/api/eol', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(eolKey, status)
    },
  })
}
