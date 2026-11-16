import { useQuery } from '@tanstack/react-query'

import { reachabilityQuery, useSetReachabilityEnabled } from '../api/reachability'
import { Button } from './ui/button'

/**
 * ReachabilityCard is the sidebar's Go reachability line, next to the EPSS
 * card. The enrichment is opt-in and off by default: with it off no
 * govulncheck process runs and Go findings carry no reachability.
 */
export function ReachabilityCard() {
  const { data } = useQuery(reachabilityQuery)
  const toggle = useSetReachabilityEnabled()

  if (!data) {
    return null
  }

  if (!data.enabled) {
    return (
      <section
        aria-label="Go reachability"
        className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
      >
        <p className="text-xs font-medium">Go reachability</p>
        <p className="text-[11px] leading-relaxed text-muted">
          Off. Runs govulncheck on Go scans when on.
        </p>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="mt-1 self-start"
          onClick={() => toggle.mutate(true)}
          disabled={toggle.isPending}
        >
          Enable Go reachability
        </Button>
      </section>
    )
  }

  return (
    <section
      aria-label="Go reachability"
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium">Go reachability</p>
        <button
          type="button"
          aria-label="Turn off Go reachability"
          title="Turn off"
          onClick={() => toggle.mutate(false)}
          disabled={toggle.isPending}
          className="text-[11px] text-faint hover:text-fg"
        >
          Off
        </button>
      </div>
      {data.available ? (
        <p className="text-[11px] text-muted">
          On. govulncheck runs on Go scans.
        </p>
      ) : (
        <>
          <p className="text-[11px] text-critical">No Go toolchain</p>
          <p className="text-[11px] text-faint">
            Install Go; findings stay unknown until then.
          </p>
        </>
      )}
    </section>
  )
}
