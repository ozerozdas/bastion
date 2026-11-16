import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { updateQuery, type UpdateStatus } from '../api/update'
import { dismissUpdate, isUpdateDismissed } from '../lib/update-dismiss'
import { Button } from './ui/button'

/**
 * UpdateNotice is the sidebar's release alert, directly above the version chip.
 * It shows a newer release when the cached check found one and renders nothing
 * when the check is off or bastion is current; the opt-in itself is a setting
 * in the settings modal (#139). The dismiss is local to this browser and scoped
 * to one release version.
 */
export function UpdateNotice() {
  const { data } = useQuery(updateQuery)

  // Disabled (env switch, CI, dev build): there is no check to report.
  if (!data || data.disabled) {
    return null
  }
  if (data.consent === 'on' && data.update_available && data.latest) {
    return <UpdateAvailableCard status={data} latest={data.latest} />
  }
  return null
}

/** UpdateAvailableCard shows the release and the command that installs it. */
function UpdateAvailableCard({
  status,
  latest,
}: {
  status: UpdateStatus
  latest: string
}) {
  const [dismissed, setDismissed] = useState(() =>
    isUpdateDismissed(window.localStorage, latest),
  )
  const [copied, setCopied] = useState(false)

  if (dismissed) {
    return null
  }

  const version = latest.startsWith('v') ? latest : `v${latest}`
  const command = status.command

  const dismiss = () => {
    dismissUpdate(window.localStorage, latest)
    setDismissed(true)
  }

  const copy = async () => {
    if (!command) {
      return
    }
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
    } catch {
      // Clipboard access can be denied outside a secure context; leaving the
      // label unchanged is better than claiming a copy that did not happen.
    }
  }

  return (
    <section
      aria-label="Release available"
      className="flex flex-col gap-1.5 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium">{version} is available</p>
        <button
          type="button"
          aria-label="Dismiss update notice"
          title="Dismiss"
          onClick={dismiss}
          className="-mt-1 -mr-1 flex size-6 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg"
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <p className="text-[0.6875rem] text-muted">
        You have {status.current.startsWith('v') ? status.current : `v${status.current}`}.
      </p>

      {command ? (
        <div className="flex min-w-0 items-center gap-1.5">
          <code className="min-w-0 flex-1 overflow-x-auto rounded-md border border-border-strong bg-bg px-2 py-1 font-mono text-[0.625rem] whitespace-nowrap">
            {command}
          </code>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => void copy()}
            aria-label="Copy update command"
          >
            <span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
          </Button>
        </div>
      ) : null}

      {status.release_url ? (
        <a
          href={status.release_url}
          target="_blank"
          rel="noopener noreferrer"
          className="self-start text-[0.6875rem] text-muted underline underline-offset-2 hover:text-fg"
        >
          Release notes
        </a>
      ) : null}
    </section>
  )
}
