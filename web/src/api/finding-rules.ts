import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

export type FindingRule = components['schemas']['FindingRule']
export type CreateFindingRule = components['schemas']['CreateFindingRuleRequest']

const rulesKey = ['finding-rules'] as const

export const findingRulesQuery = queryOptions({
  queryKey: rulesKey,
  queryFn: () => api.get<components['schemas']['FindingRuleList']>('/api/finding-rules'),
})

/** useFindingRuleAction runs a rule change and refreshes everything it closes. */
function useFindingRuleAction<T>(run: (input: T) => Promise<unknown>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: run,
    onSuccess: () => queryClient.invalidateQueries(),
  })
}

export function useCreateFindingRule() {
  return useFindingRuleAction((rule: CreateFindingRule) =>
    api.post('/api/finding-rules', rule),
  )
}

export function useApproveFindingRule() {
  return useFindingRuleAction((id: number) =>
    api.post(`/api/finding-rules/${id}/approve`),
  )
}

export function useDeleteFindingRule() {
  return useFindingRuleAction((id: number) =>
    api.remove(`/api/finding-rules/${id}`),
  )
}
