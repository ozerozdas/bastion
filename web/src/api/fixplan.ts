import { queryOptions } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** FixPlan is one asset's open vulnerabilities grouped into package upgrades. */
export type FixPlan = components['schemas']['FixPlan']
export type FixPlanStep = components['schemas']['FixPlanStep']
export type FixPlanNoFix = components['schemas']['FixPlanNoFix']
export type FixPlanFactor = components['schemas']['FixPlanFactor']

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
