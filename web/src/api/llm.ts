import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** LLMSettings is the /api/llm payload. There is no credential: the endpoint is local. */
export type LLMSettings = components['schemas']['LLMSettings']

/** SetLLMSettingsRequest is the PUT body; omitted fields are untouched. */
export type SetLLMSettingsRequest = components['schemas']['SetLLMSettingsRequest']

/** ExplainFindingResponse is one advisory explanation from the local model. */
export type ExplainFindingResponse = components['schemas']['ExplainFindingResponse']

/** LLMModels is the /api/llm/models payload: the ids the endpoint offers. */
export type LLMModels = components['schemas']['LLMModels']

export const llmKey = ['llm'] as const

/** llmQuery reads the stored local-model choices. */
export const llmQuery = queryOptions({
  queryKey: llmKey,
  queryFn: () => api.get<LLMSettings>('/api/llm'),
  staleTime: 30_000,
})

/**
 * llmModelsQuery lists the models an endpoint offers. The server makes the
 * call because the UI's CSP forbids reaching the model server directly, and it
 * only runs once the endpoint field has a value. A failure is shown inline, so
 * it is never retried in the background.
 */
export const llmModelsQuery = (endpoint: string) =>
  queryOptions({
    queryKey: [...llmKey, 'models', endpoint] as const,
    queryFn: () =>
      api.get<LLMModels>(
        `/api/llm/models?endpoint=${encodeURIComponent(endpoint)}`,
      ),
    enabled: endpoint.trim() !== '',
    staleTime: 30_000,
    retry: false,
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
