import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { healthQuery } from '../api/health'
import { cn } from '../lib/utils'

/**
 * HealthChip is the sidebar's liveness line. It is also the proof that the
 * browser, the session cookie and the API agree end to end.
 */
export function HealthChip({ action }: { action?: ReactNode }) {
  const { data, isPending, isError } = useQuery(healthQuery)

  const dot = isError
    ? 'bg-critical'
    : isPending
      ? 'bg-faint'
      : 'bg-ok'
  const label = isError
    ? 'API unreachable'
    : isPending
      ? 'Local · connecting…'
      : `Local · v${data?.version ?? 'unknown'}`

  return (
    <div className="mt-auto flex items-center gap-2 rounded-lg border border-border-subtle py-2.5 pr-2 pl-3">
      <div className="flex min-w-0 flex-col gap-1.5">
        <div className="flex items-center gap-2">
          <span
            className={cn('size-1.5 rounded-full', dot)}
            title={isError ? 'The local API is not answering' : 'Connected'}
          />
          <span className="font-mono text-[11px] text-muted">{label}</span>
        </div>
        <div className="text-[11px] text-faint">Nothing leaves your machine</div>
      </div>
      {action ? <div className="ml-auto shrink-0">{action}</div> : null}
    </div>
  )
}
