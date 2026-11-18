import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Asset is a project bastion scans, with its last scan and open counts. */
export type Asset = components['schemas']['Asset']

/** CreateAssetRequest is the POST /api/assets body. */
export type CreateAssetRequest = components['schemas']['CreateAssetRequest']

/** AssetLink is the other end of a repository <-> image link. */
export type AssetLink = components['schemas']['AssetLink']

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

/**
 * useSetAssetLink links an image to a repository by hand. The manual link
 * replaces a label-derived one and survives later scans.
 */
export function useSetAssetLink() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ imageId, repoId }: { imageId: number; repoId: number }) =>
      api.put<Asset>(`/api/assets/${imageId}/link`, { repo_asset_id: repoId }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKey }),
  })
}

/** useSetAssetSchedule sets how often bastion scans an asset while it runs. */
export function useSetAssetSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, schedule }: { id: number; schedule: Asset['scan_schedule'] }) =>
      api.put<Asset>(`/api/assets/${id}/schedule`, { schedule }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKey }),
  })
}

/** useClearAssetLink removes an image's repository link, manual or not. */
export function useClearAssetLink() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (imageId: number) => api.remove<void>(`/api/assets/${imageId}/link`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKey }),
  })
}
