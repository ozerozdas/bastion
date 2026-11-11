import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Asset is a project bastion scans, with its last scan and open counts. */
export type Asset = components['schemas']['Asset']

/** CreateAssetRequest is the POST /api/assets body. */
export type CreateAssetRequest = components['schemas']['CreateAssetRequest']

type AssetList = components['schemas']['AssetList']

export const assetsKey = ['assets'] as const

/** assetsQuery lists non-archived assets. */
export const assetsQuery = queryOptions({
  queryKey: assetsKey,
  queryFn: async () => (await api.get<AssetList>('/api/assets')).assets,
})

/** useCreateAsset adds a repo (default branch resolved via GitHub) or a local path. */
export function useCreateAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateAssetRequest) => api.post<Asset>('/api/assets', input),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKey }),
  })
}

/** useArchiveAsset removes an asset from the list; its scans stay in the DB. */
export function useArchiveAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.remove<void>(`/api/assets/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKey }),
  })
}
