import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { updateQuery, type UpdateStatus } from '../api/update'
import { useT } from '../lib/i18n'
import { dismissUpdate, isUpdateDismissed } from '../lib/update-dismiss'
import { cn } from '../lib/utils'
import { CheckIcon, CloseIcon, CopyIcon } from './icons'

/**
 * UpdateNotice is the sidebar's release alert, directly above the version chip.
 * It shows a newer release when the cached check found one and renders nothing
 * when the check is off or bastion is current; the opt-in itself is a setting
 * in the settings modal (#139). The dismiss is local to this browser and scoped
 * to one release version.
 */
export function UpdateNotice() {
  useT()
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

/**
 * Ways to update. "bastion update" comes first: it replaces the binary in
 * place and, on a Homebrew install, prints the brew command instead, so no
 * separate Homebrew option is offered.
 */
const methods = [
  { value: 'bastion', label: 'bastion' },
  { value: 'curl', label: 'curl' },
] as const

type Method = (typeof methods)[number]['value']

function commandFor(method: Method): string {
  switch (method) {
    case 'bastion':
      return 'bastion update'
    case 'curl':
      return 'curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh'
  }
}

/** UpdateAvailableCard shows the release and the command that installs it. */
function UpdateAvailableCard({
  status,
  latest,
}: {
  status: UpdateStatus
  latest: string
}) {
  const t = useT()
  const [dismissed, setDismissed] = useState(() =>
    isUpdateDismissed(window.localStorage, latest),
  )
  const [method, setMethod] = useState<Method>('bastion')
  const [copied, setCopied] = useState(false)

  if (dismissed) {
    return null
  }

  const version = latest.startsWith('v') ? latest : `v${latest}`
  const current = status.current.startsWith('v')
    ? status.current
    : `v${status.current}`
  const command = commandFor(method)

  const dismiss = () => {
    dismissUpdate(window.localStorage, latest)
    setDismissed(true)
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
    } catch {
      // Clipboard access can be denied outside a secure context; leaving the
      // icon unchanged is better than claiming a copy that did not happen.
    }
  }

  return (
    <section
      aria-label={t('update.aria')}
      className="flex flex-col gap-2.5 rounded-lg border border-border-subtle bg-surface p-3"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 flex-col gap-0.5">
          <p className="text-[0.8125rem] font-semibold">
            {t('update.available', { version })}
          </p>
          <p className="text-[0.6875rem] text-muted">
            {t('update.youHave', { version: current })}
            {status.release_url ? (
              <>
                {' · '}
                <a
                  href={status.release_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline underline-offset-2 hover:text-fg"
                >
                  {t('update.releaseNotes')}
                </a>
              </>
            ) : null}
          </p>
        </div>
        <button
          type="button"
          aria-label={t('update.dismissAria')}
          title={t('update.dismiss')}
          onClick={dismiss}
          className="-mt-1 -mr-1 flex size-6 shrink-0 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg"
        >
          <CloseIcon className="size-3.5" />
        </button>
      </div>

      <div className="flex flex-col gap-1.5">
        <div
          role="group"
          aria-label={t('update.methodAria')}
          className="flex rounded-md bg-hover p-0.5"
        >
          {methods.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={method === option.value}
              onClick={() => {
                setMethod(option.value)
                setCopied(false)
              }}
              className={cn(
                'flex-1 rounded-[5px] px-1.5 py-0.5 text-[0.6875rem] transition-colors',
                method === option.value
                  ? 'bg-surface font-medium text-fg shadow-sm'
                  : 'text-muted hover:text-fg',
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex items-start gap-1 rounded-md border border-border-subtle bg-bg py-1 pr-1 pl-2">
          <code className="min-w-0 flex-1 py-0.5 font-mono text-[0.6875rem] leading-snug break-all">
            {command}
          </code>
          <button
            type="button"
            onClick={() => void copy()}
            aria-label={copied ? t('update.copied') : t('update.copyAria')}
            title={copied ? t('update.copied') : t('update.copy')}
            className="flex size-6 shrink-0 items-center justify-center rounded text-muted transition-colors hover:bg-hover hover:text-fg"
          >
            {copied ? (
              <CheckIcon className="size-3.5 text-ok" />
            ) : (
              <CopyIcon className="size-3.5" />
            )}
          </button>
        </div>
      </div>
    </section>
  )
}
