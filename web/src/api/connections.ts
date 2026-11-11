import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Connection is a configured integration; the credential is never part of it. */
export type Connection = components['schemas']['Connection']

/** ConnectionStatus is the result of the last test. */
export type ConnectionStatus = components['schemas']['ConnectionStatus']

/** CreateConnectionRequest is the POST /api/connections body. */
export type CreateConnectionRequest =
  components['schemas']['CreateConnectionRequest']

type ConnectionList = components['schemas']['ConnectionList']

const connectionsKey = ['connections'] as const

/**
 * connectionsQuery lists every connection. There are only a handful and the
 * page shows all of them, so no pagination or per-kind view is needed.
 */
export const connectionsQuery = queryOptions({
  queryKey: connectionsKey,
  queryFn: async () => {
    const list = await api.get<ConnectionList>('/api/connections')
    return list.connections
  },
})

/** DiscoveredRepo is one repository a GitHub connection can add. */
export type DiscoveredRepo = components['schemas']['DiscoveredRepo']

type DiscoverReposResponse = components['schemas']['DiscoverReposResponse']

/**
 * discoverQuery lists the repositories the connection can read, each flagged
 * already_added when an asset with the same owner/repo reference exists.
 */
export function discoverQuery(id: number) {
  return queryOptions({
    queryKey: [...connectionsKey, 'discover', id],
    queryFn: async () => {
      const list = await api.get<DiscoverReposResponse>(
        `/api/connections/${String(id)}/discover`,
      )
      return list.repos
    },
    enabled: Number.isInteger(id) && id > 0,
  })
}

/** useCreateConnection stores the token in the keyring and tests it once. */
export function useCreateConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateConnectionRequest) =>
      api.post<Connection>('/api/connections', input),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: connectionsKey }),
  })
}

/**
 * useTestConnection re-runs `GET /user`. A failed test is a 200 with
 * `status: error` and a hint, not an API error.
 */
export function useTestConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.post<Connection>(`/api/connections/${id}/test`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: connectionsKey }),
  })
}

/** useDeleteConnection removes the row and its keyring entry. */
export function useDeleteConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.remove<void>(`/api/connections/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: connectionsKey }),
  })
}
