import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** SecurityNewsFeed is the /api/security-news payload. */
export type SecurityNewsFeed = components['schemas']['SecurityNewsFeed']

/** SecurityNewsSource is one preset feed and its toggle. */
export type SecurityNewsSource = components['schemas']['SecurityNewsSource']

/** SecurityNewsSettings is the PUT response: the stored choice. */
export type SecurityNewsSettings = components['schemas']['SecurityNewsSettings']

export const securityNewsKey = ['security-news'] as const

/** securityNewsQuery reads the server-side feed; the server caches 30 minutes. */
export const securityNewsQuery = queryOptions({
  queryKey: securityNewsKey,
  queryFn: () => api.get<SecurityNewsFeed>('/api/security-news'),
  staleTime: 5 * 60_000,
})

/** useSetSecurityNews stores the feature switch and source selection. */
export function useSetSecurityNews() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { enabled: boolean; sources?: string[] }) =>
      api.put<SecurityNewsSettings>('/api/security-news', body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: securityNewsKey })
    },
  })
}
