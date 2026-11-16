import { useQuery } from '@tanstack/react-query'

import { sastQuery, useSetSASTEnabled } from '../api/sast'
import { Button } from './ui/button'

/**
 * SASTCard is the sidebar's opt-in SAST line, next to the reachability card.
 * The module is off by default: with it off nothing is downloaded and
 * repository scans are unchanged.
 */
export function SASTCard() {
  const { data } = useQuery(sastQuery)
  const toggle = useSetSASTEnabled()

  if (!data) {
    return null
  }

  if (!data.enabled) {
    return (
      <section
        aria-label="SAST"
        className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
      >
        <p className="text-xs font-medium">SAST</p>
        <p className="text-[11px] leading-relaxed text-muted">
          Off. Downloads Opengrep {data.version} (~47 MB) and community rules
          (~1 MB) from GitHub; runs locally.
        </p>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="mt-1 self-start"
          onClick={() => toggle.mutate(true)}
          disabled={toggle.isPending}
        >
          Enable SAST
        </Button>
      </section>
    )
  }

  return (
    <section
      aria-label="SAST"
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium">SAST</p>
        <button
          type="button"
          aria-label="Turn off SAST"
          title="Turn off"
          onClick={() => toggle.mutate(false)}
          disabled={toggle.isPending}
          className="text-[11px] text-faint hover:text-fg"
        >
          Off
        </button>
      </div>
      {data.installing ? (
        <p className="font-mono text-[11px] text-muted">
          Downloading Opengrep {data.version}…
        </p>
      ) : data.install_error ? (
        <>
          <p className="text-[11px] text-critical">Download failed</p>
          <p
            className="min-w-0 truncate font-mono text-[10px] text-muted"
            title={data.install_error}
          >
            {data.install_error}
          </p>
        </>
      ) : data.state === 'installed' ? (
        <p className="text-[11px] text-muted">
          On. Opengrep {data.version} runs on repository scans.
        </p>
      ) : (
        <p className="text-[11px] text-muted">
          On. The module is not installed yet; the next scan downloads it.
        </p>
      )}
    </section>
  )
}
