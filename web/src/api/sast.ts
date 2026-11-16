import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** SASTStatus is the /api/sast payload. */
export type SASTStatus = components['schemas']['SASTStatus']

export const sastKey = ['sast'] as const

/**
 * sastQuery reads the opt-in SAST module state. While a download is running it
 * polls, so the card turns from "downloading" to "installed" without a reload.
 */
export const sastQuery = queryOptions({
  queryKey: sastKey,
  queryFn: () => api.get<SASTStatus>('/api/sast'),
  staleTime: 60_000,
  // A download starts on the next scan as well as on enable, so poll whenever
  // the setting is on but the module is not installed and no download has
  // failed. A failed install stops the poll: the card shows the error instead.
  refetchInterval: (query) => {
    const data = query.state.data
    return data?.enabled && data.state !== 'installed' && !data.install_error
      ? 2_000
      : false
  },
})

/** useSetSASTEnabled stores the choice and replaces the cached state. */
export function useSetSASTEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) => api.put<SASTStatus>('/api/sast', { enabled }),
    onSuccess: (status) => {
      queryClient.setQueryData(sastKey, status)
      void queryClient.invalidateQueries({ queryKey: sastKey })
    },
  })
}
