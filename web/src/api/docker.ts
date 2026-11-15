import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { assetsKey } from './assets'
import { ApiError, api } from './client'
import { scansKey } from './scans'
import type { components } from './schema'

/** DockerImage is one tagged image on the local Docker daemon. */
export type DockerImage = components['schemas']['DockerImage']

type DockerImageList = components['schemas']['DockerImageList']
type Asset = components['schemas']['Asset']
type AssetList = components['schemas']['AssetList']
type ScanQueueResult = components['schemas']['ScanQueueResult']

/** dockerImagesQuery reads the daemon state and its tagged images. */
export const dockerImagesQuery = queryOptions({
  queryKey: ['docker', 'images'],
  queryFn: () => api.get<DockerImageList>('/api/docker/images'),
})

/**
 * useScanDockerImage tracks an image and queues a scan for it. An image that is
 * already tracked answers 409; that is not an error, the existing asset is
 * scanned instead.
 */
export function useScanDockerImage() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (image: DockerImage) => {
      let assetId: number
      try {
        const asset = await api.post<Asset>('/api/assets', {
          kind: 'image',
          ref: image.reference,
        })
        assetId = asset.id
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 409) {
          throw error
        }
        const list = await api.get<AssetList>('/api/assets')
        const existing = list.assets.find(
          (asset) => asset.kind === 'image' && asset.ref === image.reference,
        )
        if (!existing) {
          throw error
        }
        assetId = existing.id
      }
      return api.post<ScanQueueResult>('/api/scans', { asset_ids: [assetId] })
    },
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: assetsKey }),
        queryClient.invalidateQueries({ queryKey: scansKey }),
      ]),
  })
}
