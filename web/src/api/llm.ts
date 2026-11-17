import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** LLMSettings is the /api/llm payload. There is no credential: the endpoint is local. */
export type LLMSettings = components['schemas']['LLMSettings']

/** SetLLMSettingsRequest is the PUT body; omitted fields are untouched. */
export type SetLLMSettingsRequest = components['schemas']['SetLLMSettingsRequest']

/** ExplainFindingResponse is one advisory explanation from the local model. */
export type ExplainFindingResponse = components['schemas']['ExplainFindingResponse']

export const llmKey = ['llm'] as const

/** llmQuery reads the stored local-model choices. */
export const llmQuery = queryOptions({
  queryKey: llmKey,
  queryFn: () => api.get<LLMSettings>('/api/llm'),
  staleTime: 30_000,
})

/** useSetLLMSettings stores the choices and replaces the cached settings. */
export function useSetLLMSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SetLLMSettingsRequest) =>
      api.put<LLMSettings>('/api/llm', body),
    onSuccess: (settings) => {
      queryClient.setQueryData(llmKey, settings)
    },
  })
}

/**
 * useExplainFinding asks the local model to explain one finding. It is a
 * mutation, not a query, because the answer is generated on demand and must
 * not be cached or refetched in the background.
 */
export function useExplainFinding() {
  return useMutation({
    mutationFn: ({ assetId, fingerprint }: { assetId: number; fingerprint: string }) =>
      api.post<ExplainFindingResponse>(
        `/api/assets/${String(assetId)}/findings/${encodeURIComponent(fingerprint)}/explain`,
      ),
  })
}
