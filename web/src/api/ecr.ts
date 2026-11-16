import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { t } from '../lib/i18n'
import { assetsKey } from './assets'
import { ApiError, api } from './client'
import { scansKey } from './scans'
import type { components } from './schema'

/** EcrRepository is one ECR repository with its newest tags. */
export type EcrRepository = components['schemas']['EcrRepository']

/** EcrTag is one ECR image tag and the digest it points at. */
export type EcrTag = components['schemas']['EcrTag']

type DiscoverReposResponse = components['schemas']['DiscoverReposResponse']
type Asset = components['schemas']['Asset']
type AssetList = components['schemas']['AssetList']
type ScanQueueResult = components['schemas']['ScanQueueResult']

/**
 * ecrDiscoverQuery lists the ECR repositories an AWS connection can read, with
 * each repository's newest tags. The endpoint is shared with GitHub discovery;
 * an AWS connection answers `ecr_repositories`.
 */
export function ecrDiscoverQuery(id: number) {
  return queryOptions({
    queryKey: ['connections', 'discover', id, 'ecr'],
    queryFn: async () => {
      const list = await api.get<DiscoverReposResponse>(
        `/api/connections/${String(id)}/discover`,
      )
      return list.ecr_repositories ?? []
    },
    enabled: Number.isInteger(id) && id > 0,
  })
}

/**
 * useScanEcrImage tracks a digest-pinned ECR tag and queues a scan for it. An
 * already tracked image answers 409; that is not an error, the existing asset
 * is scanned instead.
 */
export function useScanEcrImage(connectionId: number) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (tag: EcrTag) => {
      const primary = tag.tags[0]
      if (!primary) {
        throw new Error(t('error.ecrNoTag'))
      }
      let assetId: number
      try {
        const asset = await api.post<Asset>('/api/assets', {
          kind: 'image',
          ref: tag.ref,
          tag: primary,
          connection_id: connectionId,
        })
        assetId = asset.id
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 409) {
          throw error
        }
        const list = await api.get<AssetList>('/api/assets')
        const existing = list.assets.find(
          (asset) => asset.kind === 'image' && asset.ref === tag.ref,
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
