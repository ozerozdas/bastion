import { queryOptions, useMutation } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** FixPlan is one asset's open vulnerabilities grouped into package upgrades. */
export type FixPlan = components['schemas']['FixPlan']
export type FixPlanStep = components['schemas']['FixPlanStep']
export type FixPlanNoFix = components['schemas']['FixPlanNoFix']
export type FixPlanFactor = components['schemas']['FixPlanFactor']

/** FixPlanPullRequestRequest is the POST body of a confirmed manifest bump. */
export type FixPlanPullRequestRequest =
  components['schemas']['FixPlanPullRequestRequest']

/** FixPlanPullRequestResult is the pull request that was opened. */
export type FixPlanPullRequestResult =
  components['schemas']['FixPlanPullRequestResult']

export const fixPlanKey = ['fix-plan'] as const

/** fixPlanQuery reads GET /api/assets/{id}/fix-plan; it stays idle without an asset. */
export function fixPlanQuery(assetId: number | undefined) {
  return queryOptions({
    queryKey: [...fixPlanKey, assetId],
    queryFn: async () =>
      api.get<FixPlan>(`/api/assets/${String(assetId)}/fix-plan`),
    enabled: assetId !== undefined,
  })
}

/**
 * useOpenFixPlanPullRequest opens a pull request for one confirmed step (#47).
 * Nothing is sent until the dialog's confirm button calls mutate, so a user who
 * closes the dialog never creates a branch on GitHub.
 */
export function useOpenFixPlanPullRequest(assetId: number | undefined) {
  return useMutation({
    mutationFn: (input: FixPlanPullRequestRequest) =>
      api.post<FixPlanPullRequestResult>(
        `/api/assets/${String(assetId)}/fix-plan/pull-request`,
        input,
      ),
  })
}
