import { queryOptions } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** Health is the /api/health payload. */
export type Health = components['schemas']['Health']

/** healthQuery is the liveness probe the shell and dashboard both read. */
export const healthQuery = queryOptions({
  queryKey: ['health'],
  queryFn: () => api.get<Health>('/api/health'),
  // It only reports that the process is up, which happens once per process.
  staleTime: Number.POSITIVE_INFINITY,
})
