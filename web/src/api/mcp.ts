import { queryOptions } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** MCPSetup is the /api/mcp payload. */
export type MCPSetup = components['schemas']['MCPSetup']

/**
 * mcpQuery reads the command that starts `bastion mcp`. It is fixed for the
 * life of the server process, so it is never refetched.
 */
export const mcpQuery = queryOptions({
  queryKey: ['mcp'],
  queryFn: () => api.get<MCPSetup>('/api/mcp'),
  staleTime: Number.POSITIVE_INFINITY,
})
