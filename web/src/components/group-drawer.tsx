import { useState, type FormEvent } from 'react'

import {
  useBulkFindingState,
  type Finding,
  type FindingState,
} from '../api/findings'
import type { FindingGroup } from '../lib/group-findings'
import { capitalize, severityTone, typeLabels } from '../lib/finding-labels'
import { useDrawerFocus } from './drawer-focus'
import { ErrorNote } from './error-note'
import { Badge } from './ui/badge'
import { Button } from './ui/button'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

export type GroupDrawerProps = {
  group: FindingGroup
  assetNames: ReadonlyMap<number, string>
  onClose: () => void
  /** onRemoving runs before a decision is sent, as in FindingDrawer (issue #75). */
  onRemoving: () => void
  onRemoveFailed: () => void
  /** onOpenFinding opens one member's own drawer. */
  onOpenFinding: (finding: Finding) => void
}

/**
 * GroupDrawer lists one rule's findings across projects (#90). A decision here
 * applies to every affected project at once, after a confirm step that states
 * how many findings it hides.
 */
export function GroupDrawer({
  group,
  assetNames,
  onClose,
  onRemoving,
  onRemoveFailed,
  onOpenFinding,
}: GroupDrawerProps) {
  const { panel, onKeyDown } = useDrawerFocus(onClose)
  const bulk = useBulkFindingState()
  const [confirming, setConfirming] = useState(false)
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')

  const projectsLabel =
    group.projectCount === 1 ? '1 project' : `${String(group.projectCount)} projects`
  const target = group.findings.map((finding) => ({
    assetId: finding.asset_id,
    fingerprint: finding.fingerprint,
  }))
  const ignored = group.findings.filter((finding) => finding.status === 'ignored')

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onRemoving()
    bulk.mutate(
      { findings: target, decision: { state: decision, reason: reason.trim() } },
      { onSuccess: onClose, onError: onRemoveFailed },
    )
  }

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
        aria-labelledby="group-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="absolute inset-y-0 right-0 flex w-full max-w-[520px] flex-col gap-4 overflow-y-auto border-l border-border-subtle bg-surface p-5 shadow-xl focus:outline-none"
      >
        <div className="flex items-start gap-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <h2 id="group-title" className="text-[15px] font-semibold break-words">
              {group.title}
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={severityTone[group.severity]}>
                {group.severity === 'unknown'
                  ? 'unknown'
                  : capitalize(group.severity)}
              </Badge>
              <Badge>{typeLabels[group.type]}</Badge>
              <span className="text-xs text-faint">
                {group.findings.length === 1
                  ? `1 finding in ${projectsLabel}`
                  : `${String(group.findings.length)} findings in ${projectsLabel}`}
              </span>
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

        {group.ruleId ? (
          <p className="font-mono text-xs break-all text-muted">{group.ruleId}</p>
        ) : null}

        <section className="flex flex-col gap-2">
          <h3 className="text-[13px] font-semibold">Affected projects</h3>
          <ul className="flex flex-col gap-1.5">
            {group.findings.map((finding) => {
              const project =
                assetNames.get(finding.asset_id) ?? `Asset ${String(finding.asset_id)}`
              const installed =
                finding.package_name === undefined
                  ? undefined
                  : finding.package_version === undefined
                    ? finding.package_name
                    : `${finding.package_name}@${finding.package_version}`
              return (
                <li key={`${String(finding.asset_id)}-${finding.fingerprint}`}>
                  <button
                    type="button"
                    onClick={() => onOpenFinding(finding)}
                    className="flex w-full flex-col gap-1 rounded-md border border-border-subtle bg-bg p-2.5 text-left hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
                  >
                    <span className="flex flex-wrap items-center gap-2 text-[13px]">
                      <span className="font-medium">{project}</span>
                      <span className="font-mono text-xs text-muted">
                        {installed ?? 'no package'}
                        <span aria-hidden="true"> → </span>
                        <span className="sr-only">fixed in </span>
                        {finding.fixed_version ?? 'no fixed version'}
                      </span>
                    </span>
                    <span className="text-xs text-faint">Open this finding</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </section>

        <section className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
          <h3 className="text-[13px] font-semibold">Decision</h3>

          {ignored.length === group.findings.length ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={bulk.isPending}
                onClick={() => {
                  onRemoving()
                  bulk.mutate(
                    {
                      findings: group.findings.map((finding) => ({
                        assetId: finding.asset_id,
                        fingerprint: finding.fingerprint,
                      })),
                    },
                    { onSuccess: onClose, onError: onRemoveFailed },
                  )
                }}
              >
                {bulk.isPending
                  ? 'Reopening…'
                  : `Reopen in all ${projectsLabel}`}
              </Button>
              <span className="text-xs text-faint">
                The findings return to future scans.
              </span>
            </div>
          ) : confirming ? (
            <form onSubmit={submit} className="flex flex-col gap-2">
              <p className="text-xs text-muted">
                Ignore this finding in all {projectsLabel}?{' '}
                {target.length === 1
                  ? '1 finding will be hidden'
                  : `${String(target.length)} findings will be hidden`}{' '}
                with this reason, and the decision applies to later scans too.
              </p>
              <div className="flex flex-col gap-1">
                <label
                  htmlFor="group-decision"
                  className="text-xs font-medium text-muted"
                >
                  Hide in every project as
                </label>
                <select
                  id="group-decision"
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
                  htmlFor="group-reason"
                  className="text-xs font-medium text-muted"
                >
                  Reason
                </label>
                <textarea
                  id="group-reason"
                  required
                  rows={3}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="Why every project can hide this finding, for the next person who reads it."
                  className="w-full rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-[13px] text-fg placeholder:text-faint"
                />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="submit"
                  size="sm"
                  disabled={bulk.isPending || reason.trim() === ''}
                >
                  {bulk.isPending
                    ? 'Saving…'
                    : `Hide ${String(target.length)} in ${projectsLabel}`}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setConfirming(false)}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setConfirming(true)}
              >
                Ignore in all {projectsLabel}…
              </Button>
              <span className="text-xs text-faint">
                Asks for a reason first, then hides every project’s finding.
              </span>
            </div>
          )}

          {bulk.isError ? (
            <ErrorNote
              error={bulk.error}
              fix="Projects before the failure were saved; the list shows what is left."
            />
          ) : null}
        </section>
      </div>
    </div>
  )
}
