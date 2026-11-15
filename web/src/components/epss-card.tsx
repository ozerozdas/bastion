import { useQuery } from '@tanstack/react-query'

import { epssQuery, useSetEPSSEnabled } from '../api/epss'
import { Button } from './ui/button'

/**
 * EPSSCard is the sidebar's EPSS line, next to the release-check card.
 *
 * The feed is opt-in and off by default: with the setting off nothing is
 * downloaded and findings carry no score. When on, the card shows the feed's
 * own score date and how many CVEs it covers, or the last failure.
 */
export function EPSSCard() {
  const { data } = useQuery(epssQuery)
  const toggle = useSetEPSSEnabled()

  if (!data) {
    return null
  }

  if (!data.enabled) {
    return (
      <section
        aria-label="EPSS exploit scores"
        className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
      >
        <p className="text-xs font-medium">EPSS exploit scores</p>
        <p className="text-[11px] leading-relaxed text-muted">
          Off. One request a day to FIRST.org when on.
        </p>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="mt-1 self-start"
          onClick={() => toggle.mutate(true)}
          disabled={toggle.isPending}
        >
          Turn on
        </Button>
      </section>
    )
  }

  return (
    <section
      aria-label="EPSS exploit scores"
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium">EPSS exploit scores</p>
        <button
          type="button"
          aria-label="Turn off EPSS scores"
          title="Turn off"
          onClick={() => toggle.mutate(false)}
          disabled={toggle.isPending}
          className="text-[11px] text-faint hover:text-fg"
        >
          Off
        </button>
      </div>
      {data.error ? (
        <>
          <p className="text-[11px] text-critical">Download failed</p>
          <p
            className="min-w-0 truncate font-mono text-[10px] text-muted"
            title={data.error}
          >
            {data.error}
          </p>
          <p className="text-[11px] text-faint">Retries daily.</p>
        </>
      ) : data.count === undefined ? (
        <p className="font-mono text-[11px] text-muted">Downloading scores…</p>
      ) : (
        <p className="text-[11px] text-muted">
          <span className="tabular-nums">{data.count.toLocaleString()}</span> CVEs
          {data.score_date ? ` · ${data.score_date.slice(0, 10)}` : ''}
        </p>
      )}
    </section>
  )
}
