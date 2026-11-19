import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { ApiError, api } from './client'
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
 * ensureImageAsset tracks an image without scanning it. POST /api/assets is
 * idempotent for this purpose: a 409 means the image is already tracked, and
 * the existing asset's id is what the link or schedule needs.
 */
export async function ensureImageAsset(input: {
  ref: string
  /** ECR only: the tag the digest came from. */
  tag?: string
  /** ECR only: the AWS connection the image belongs to. */
  connectionId?: number
}): Promise<number> {
  const body: CreateAssetRequest = {
    kind: 'image',
    ref: input.ref,
    ...(input.tag === undefined ? {} : { tag: input.tag }),
    ...(input.connectionId === undefined
      ? {}
      : { connection_id: input.connectionId }),
  }
  try {
    return (await api.post<Asset>('/api/assets', body)).id
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 409) throw error
    const list = await api.get<AssetList>('/api/assets')
    const existing = list.assets.find(
      (asset) => asset.kind === 'image' && asset.ref === input.ref,
    )
    if (existing === undefined) throw error
    return existing.id
  }
}

/** useEnsureImageAsset tracks an image on demand, refreshing the asset list. */
export function useEnsureImageAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ensureImageAsset,
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
