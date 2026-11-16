import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { assetsKey } from './assets'
import { api } from './client'
import type { components } from './schema'

/** LicencePolicy is one scope's allow and deny lists. */
export type LicencePolicy = components['schemas']['LicencePolicy']

/** licencePolicyKey scopes the cache to the global policy or one asset. */
export function licencePolicyKey(assetId?: number) {
  return ['licence-policy', assetId ?? 'global'] as const
}

/** licencePolicyPath is the endpoint of a scope. */
function licencePolicyPath(assetId?: number) {
  return assetId === undefined
    ? '/api/licence-policy'
    : `/api/licence-policy?asset_id=${String(assetId)}`
}

/**
 * licencePolicyQuery reads one scope's policy. Omitting the asset id reads the
 * global policy.
 */
export function licencePolicyQuery(assetId?: number) {
  return queryOptions({
    queryKey: licencePolicyKey(assetId),
    queryFn: () => api.get<LicencePolicy>(licencePolicyPath(assetId)),
    staleTime: 30_000,
  })
}

/**
 * useSetLicencePolicy replaces one scope's policy. The findings list, grouped
 * counts, dashboard and asset counts all read the policy, so they are
 * invalidated together.
 */
export function useSetLicencePolicy(assetId?: number) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (policy: LicencePolicy) =>
      api.put<LicencePolicy>(licencePolicyPath(assetId), policy),
    onSuccess: (policy) => {
      queryClient.setQueryData(licencePolicyKey(assetId), policy)
      void queryClient.invalidateQueries({ queryKey: ['findings'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      void queryClient.invalidateQueries({ queryKey: assetsKey })
    },
  })
}
