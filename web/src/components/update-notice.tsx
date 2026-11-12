import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import {
  updateQuery,
  useSetUpdateConsent,
  type UpdateStatus,
} from '../api/update'
import { dismissUpdate, isUpdateDismissed } from '../lib/update-dismiss'
import { Button } from './ui/button'

/**
 * UpdateNotice is the sidebar's release card, directly above the version chip.
 *
 * It asks once (consent `unset`), shows a newer release when the cached check
 * found one, and renders nothing when the user declined or bastion is current.
 * The dismiss is local to this browser and scoped to one release version.
 */
export function UpdateNotice() {
  const { data } = useQuery(updateQuery)

  // Disabled (env switch, CI, dev build): asking would promise a check that
  // cannot run.
  if (!data || data.disabled) {
    return null
  }
  if (data.consent === 'unset') {
    return <ConsentCard />
  }
  if (data.consent === 'on' && data.update_available && data.latest) {
    return <UpdateAvailableCard status={data} latest={data.latest} />
  }
  return null
}

/** ConsentCard is the one-time question; the answer is stored by the API. */
function ConsentCard() {
  const consent = useSetUpdateConsent()

  return (
    <section
      aria-label="Release check"
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <p className="text-xs font-medium">Check for new releases?</p>
      <p className="text-[11px] leading-relaxed text-muted">
        One request a day to github.com. Nothing else leaves your machine.
      </p>
      <div className="mt-1 flex gap-1.5">
        <Button
          type="button"
          size="sm"
          onClick={() => consent.mutate(true)}
          disabled={consent.isPending}
        >
          Turn on
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => consent.mutate(false)}
          disabled={consent.isPending}
        >
          No thanks
        </Button>
      </div>
    </section>
  )
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
      <p className="text-[11px] text-muted">
        You have {status.current.startsWith('v') ? status.current : `v${status.current}`}.
      </p>

      {command ? (
        <div className="flex min-w-0 items-center gap-1.5">
          <code className="min-w-0 flex-1 overflow-x-auto rounded-md border border-border-strong bg-bg px-2 py-1 font-mono text-[10px] whitespace-nowrap">
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
          className="self-start text-[11px] text-muted underline underline-offset-2 hover:text-fg"
        >
          Release notes
        </a>
      ) : null}
    </section>
  )
}
