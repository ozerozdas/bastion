import { Link } from '@tanstack/react-router'

import { healthQuery } from '../api/health'
import { useQuery } from '@tanstack/react-query'

import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { buttonVariants } from '../components/ui/button'

export function DashboardPage() {
  const health = useQuery(healthQuery)

  return (
    <>
      <EmptyState
        title="No scans yet"
        body="Connect a source, add the projects you care about, then run a scan. Totals by severity, findings by type and the trend of open critical and high findings appear here after the first run."
      >
        <Link to="/connections" className={buttonVariants()}>
          Connect a source
        </Link>
        <Link to="/projects" className={buttonVariants({ variant: 'outline' })}>
          Add projects
        </Link>
      </EmptyState>

      <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 className="text-[13px] font-semibold">Local API</h2>
          <span className="text-faint">GET /api/health</span>
          <span className="ml-auto">
            {health.isPending ? (
              <Badge>checking</Badge>
            ) : health.isError ? (
              <Badge tone="critical">unreachable</Badge>
            ) : (
              <Badge tone="ok">ok</Badge>
            )}
          </span>
        </div>
        <p className="font-mono text-xs text-muted">
          {health.isPending
            ? 'connecting to the local server…'
            : health.isError
              ? `no answer: ${health.error.message}`
              : `status ${health.data.status} · version ${health.data.version}`}
        </p>
      </section>
    </>
  )
}
