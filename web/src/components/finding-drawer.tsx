import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from 'react'

import {
  useClearFindingState,
  useSetFindingState,
  type Finding,
  type FindingState,
} from '../api/findings'
import { capitalize, severityTone, stateLabels, typeLabels } from '../lib/finding-labels'
import { isHttpsUrl } from '../lib/urls'
import { ErrorNote } from './error-note'
import { Badge } from './ui/badge'
import { Button } from './ui/button'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

export type FindingDrawerProps = {
  finding: Finding
  onClose: () => void
  /**
   * onRemoving runs before a decision or reopen is sent. It cannot wait for
   * success: the refetch can drop the row and unmount this drawer first, and
   * then mutate's own callbacks never run.
   */
  onRemoving: () => void
  /** onRemoveFailed undoes onRemoving when the request fails. */
  onRemoveFailed: () => void
}

/**
 * FindingDrawer shows one finding's detail (§7.4). Scanner text is untrusted
 * (§4.3): the description is plain text and only https references become links.
 */
export function FindingDrawer({
  finding,
  onClose,
  onRemoving,
  onRemoveFailed,
}: FindingDrawerProps) {
  const panel = useRef<HTMLDivElement>(null)
  const setState = useSetFindingState()
  const clearState = useClearFindingState()
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')

  // Focus moves into the drawer when it opens, so Escape and Tab work at once.
  // Closing without a decision gives it back to the opener row; a decision
  // removes that row, so the page restores focus once the list refreshes (#69).
  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null
    panel.current?.focus()
    return () => {
      if (opener?.isConnected) opener.focus()
    }
  }, [])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onRemoving()
    setState.mutate(
      {
        asset_id: finding.asset_id,
        fingerprint: finding.fingerprint,
        state: decision,
        reason: reason.trim(),
      },
      { onSuccess: onClose, onError: onRemoveFailed },
    )
  }

  const packageLabel =
    finding.package_name === undefined
      ? undefined
      : finding.package_version === undefined
        ? finding.package_name
        : `${finding.package_name}@${finding.package_version}`

  return (
    <div className="fixed inset-0 z-40">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="absolute inset-0 bg-black/20"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            event.stopPropagation()
            onClose()
            return
          }
          if (panel.current) trapTab(event, panel.current)
        }}
        className="absolute inset-y-0 right-0 flex w-full max-w-[460px] flex-col gap-4 overflow-y-auto border-l border-border-subtle bg-surface p-5 shadow-xl focus:outline-none"
      >
        <div className="flex items-start gap-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <h2 id="finding-title" className="text-[15px] font-semibold break-words">
              {finding.title}
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={severityTone[finding.severity]}>
                {finding.severity === 'unknown'
                  ? 'unknown'
                  : capitalize(finding.severity)}
              </Badge>
              <Badge>{typeLabels[finding.type]}</Badge>
              {finding.type === 'license' ? (
                <span className="text-xs text-faint">
                  informational, no action needed
                </span>
              ) : null}
              {finding.state ? (
                <Badge tone="neutral">{stateLabels[finding.state]}</Badge>
              ) : null}
            </div>
          </div>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="ml-auto shrink-0"
            onClick={onClose}
          >
            Close
          </Button>
        </div>

        {finding.description ? (
          <p className="text-[13px] break-words whitespace-pre-wrap text-muted">
            {finding.description}
          </p>
        ) : (
          <p className="text-xs text-faint">No description was reported.</p>
        )}

        <dl className="grid grid-cols-[7rem_1fr] items-baseline gap-x-3 gap-y-1.5 text-[13px]">
          <dt className="text-muted">Scanner</dt>
          <dd className="font-mono text-xs">{finding.scanner}</dd>

          {finding.rule_id ? (
            <>
              <dt className="text-muted">Rule</dt>
              <dd className="font-mono text-xs break-all">{finding.rule_id}</dd>
            </>
          ) : null}

          {packageLabel ? (
            <>
              <dt className="text-muted">Package</dt>
              <dd className="font-mono text-xs break-all">{packageLabel}</dd>
            </>
          ) : null}

          {finding.fixed_version ? (
            <>
              <dt className="text-muted">Fixed in</dt>
              <dd className="font-mono text-xs break-all">{finding.fixed_version}</dd>
            </>
          ) : (
            <>
              <dt className="text-muted">Fix</dt>
              <dd className="text-xs text-muted">No fixed version reported.</dd>
            </>
          )}

          {finding.location ? (
            <>
              <dt className="text-muted">Location</dt>
              <dd className="font-mono text-xs break-all">{finding.location}</dd>
            </>
          ) : null}

          <dt className="text-muted">Occurrences</dt>
          <dd className="tabular-nums">{finding.occurrences}</dd>

          {finding.first_seen_scan_id !== undefined ? (
            <>
              <dt className="text-muted">First seen</dt>
              <dd className="tabular-nums">scan {finding.first_seen_scan_id}</dd>
            </>
          ) : null}

          <dt className="text-muted">Fingerprint</dt>
          <dd className="font-mono text-[11px] break-all text-muted">
            {finding.fingerprint}
          </dd>
        </dl>

        <section className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
          <h3 className="text-[13px] font-semibold">Decision</h3>

          {finding.state ? (
            <>
              <p className="text-xs text-muted">
                Marked{' '}
                <span className="text-fg">{stateLabels[finding.state]}</span>
                {finding.reason ? `: ${finding.reason}` : '.'}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    onRemoving()
                    clearState.mutate(
                      {
                        fingerprint: finding.fingerprint,
                        assetId: finding.asset_id,
                      },
                      { onSuccess: onClose, onError: onRemoveFailed },
                    )
                  }}
                  disabled={clearState.isPending}
                >
                  {clearState.isPending ? 'Reopening…' : 'Reopen'}
                </Button>
                <span className="text-xs text-faint">
                  The finding returns to future scans.
                </span>
              </div>
              {clearState.isError ? <ErrorNote error={clearState.error} /> : null}
            </>
          ) : (
            <form onSubmit={submit} className="flex flex-col gap-2">
              <div className="flex flex-col gap-1">
                <label
                  htmlFor="finding-decision"
                  className="text-xs font-medium text-muted"
                >
                  Hide this finding as
                </label>
                <select
                  id="finding-decision"
                  value={decision}
                  onChange={(event) => setDecision(event.target.value as FindingState)}
                  className={`${inputClass} w-56`}
                >
                  <option value="ignored">Ignored</option>
                  <option value="accepted_risk">Accepted risk</option>
                  <option value="false_positive">False positive</option>
                </select>
              </div>

              <div className="flex flex-col gap-1">
                <label
                  htmlFor="finding-reason"
                  className="text-xs font-medium text-muted"
                >
                  Reason
                </label>
                <textarea
                  id="finding-reason"
                  required
                  rows={3}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="Why this finding can be hidden, for the next person who reads it."
                  className="w-full rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-[13px] text-fg placeholder:text-faint"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="submit"
                  size="sm"
                  disabled={setState.isPending || reason.trim() === ''}
                >
                  {setState.isPending ? 'Saving…' : 'Save decision'}
                </Button>
                <span className="text-xs text-faint">
                  Applies to later scans of this project too.
                </span>
              </div>
            </form>
          )}

          {setState.isError ? (
            <ErrorNote error={setState.error} fix="Add a reason and try again." />
          ) : null}
        </section>

        {finding.references.length > 0 ? (
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13px] font-semibold">References</h3>
            <ul className="flex flex-col gap-1 text-xs">
              {finding.references.map((reference, index) => (
                <li key={`${String(index)}-${reference}`} className="break-all">
                  {isHttpsUrl(reference) ? (
                    <a
                      href={reference}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="underline underline-offset-2 hover:text-fg"
                    >
                      {reference}
                    </a>
                  ) : (
                    <span className="text-muted">{reference}</span>
                  )}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </div>
    </div>
  )
}

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function trapTab(event: KeyboardEvent<HTMLElement>, container: HTMLElement) {
  if (event.key !== 'Tab') return

  const items = Array.from(
    container.querySelectorAll<HTMLElement>(focusableSelector),
  )
  if (items.length === 0) {
    event.preventDefault()
    container.focus()
    return
  }

  const first = items[0]
  const last = items[items.length - 1]
  const active = document.activeElement

  if (!container.contains(active)) {
    event.preventDefault()
    first.focus()
  } else if (event.shiftKey && (active === first || active === container)) {
    // The panel itself holds focus right after open, so Shift+Tab from there wraps too.
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && active === last) {
    event.preventDefault()
    first.focus()
  }
}
