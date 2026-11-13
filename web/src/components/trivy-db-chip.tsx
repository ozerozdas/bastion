import { useQuery } from '@tanstack/react-query'

import { trivyDBQuery, useDownloadTrivyDB } from '../api/trivy-db'
import { trivyDBView } from '../lib/trivy-db'
import { Button } from './ui/button'

/**
 * TrivyDBChip is the sidebar's vulnerability DB line, above the version chip.
 *
 * It only reads the cached status on load; the ~1.7 GB download starts when the
 * user asks for it (or when a scan needs the DB, which the API reports here).
 */
export function TrivyDBChip() {
  const { data } = useQuery(trivyDBQuery)
  const download = useDownloadTrivyDB()
  const view = trivyDBView(data)

  switch (view.kind) {
    case 'missing':
      return (
        <section
          aria-label="Vulnerability database"
          className="flex flex-col gap-1.5 rounded-lg border border-border-subtle bg-surface p-2.5"
        >
          <p className="text-xs font-medium">Vulnerability DB not downloaded</p>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="self-start"
            aria-label="Download vulnerability database (about 1.7 GB)"
            onClick={() => download.mutate()}
            disabled={download.isPending}
          >
            Download (~1.7 GB)
          </Button>
        </section>
      )

    case 'downloading':
      return (
        <div
          role="status"
          aria-label="Downloading vulnerability database"
          className="flex items-center gap-2 rounded-lg border border-border-subtle py-2.5 pr-2 pl-3"
        >
          <span
            aria-hidden="true"
            className="size-3 shrink-0 rounded-full border-2 border-border-strong border-t-accent motion-safe:animate-spin"
          />
          <span className="min-w-0 font-mono text-[11px] text-muted">
            Downloading vulnerability DB…
            {view.fromScan ? ' · started by a scan' : ''}
          </span>
        </div>
      )

    case 'failed':
      return (
        <section
          aria-label="Vulnerability database"
          className="flex flex-col gap-1.5 rounded-lg border border-border-subtle bg-surface p-2.5"
        >
          <p className="text-xs font-medium text-critical">
            Vulnerability DB download failed
          </p>
          {view.error ? (
            <p
              className="min-w-0 truncate font-mono text-[10px] text-muted"
              title={view.error}
            >
              {view.error}
            </p>
          ) : null}
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="self-start"
            aria-label="Retry vulnerability database download"
            onClick={() => download.mutate()}
            disabled={download.isPending}
          >
            Retry
          </Button>
        </section>
      )

    case 'hidden':
      return null
  }
}
