import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import {
  useEffect,
  useRef,
  useState,
  type ComponentProps,
  type FormEvent,
  type KeyboardEvent,
} from 'react'

import { assetsQuery } from '../api/assets'
import { ApiError } from '../api/client'
import {
  latestFindingsQuery,
  useBulkFindingState,
  useClearFindingState,
  useSetFindingState,
  type Finding,
  type FindingState,
  type FindingStatus,
  type FindingType,
  type Severity,
} from '../api/findings'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { isHttpsUrl } from '../lib/urls'
import { cn } from '../lib/utils'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

/** typeLabels names each finding kind; license findings are informational (§8). */
const typeLabels: Record<FindingType, string> = {
  vulnerability: 'Vulnerability',
  secret: 'Secret',
  outdated: 'Outdated package',
  misconfig: 'Misconfiguration',
  license: 'License',
  malware: 'Malware',
  sast: 'Code issue',
}

const typeOptions: FindingType[] = [
  'vulnerability',
  'secret',
  'outdated',
  'misconfig',
  'license',
  'malware',
  'sast',
]

const severityOptions: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']

/** severityTone keeps severity colour on the badge only (§7). */
const severityTone: Record<
  Severity,
  'critical' | 'high' | 'medium' | 'low' | 'neutral'
> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'neutral',
}

const stateLabels: Record<FindingState, string> = {
  ignored: 'Ignored',
  accepted_risk: 'Accepted risk',
  false_positive: 'False positive',
}

/** ReportsPage is §7.4: one project's findings, filtered, with a detail drawer. */
export function ReportsPage() {
  const search = useSearch({ from: '/security-reports' })
  const navigate = useNavigate()
  const assets = useQuery(assetsQuery)

  const [type, setType] = useState<FindingType | ''>('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<FindingStatus>('open')
  const [openFingerprint, setOpenFingerprint] = useState<string | null>(null)
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())

  const assetList = assets.data ?? []
  // The URL wins; otherwise the first project keeps the page useful on arrival.
  const selected = assetList.find((asset) => asset.id === search.asset) ?? assetList[0]

  const findings = useQuery({
    ...latestFindingsQuery({
      assetId: selected?.id,
      type: type === '' ? undefined : type,
      severity: severity === '' ? undefined : severity,
      status,
    }),
    enabled: selected !== undefined,
  })

  if (assets.isPending) {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">Loading reports…</p>
      </section>
    )
  }

  if (assets.isError) {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[13px] font-semibold">Projects failed to load</h2>
        <ErrorNote error={assets.error} />
      </section>
    )
  }

  if (assetList.length === 0) {
    return (
      <EmptyState
        title="No projects yet"
        body="A security report covers one project at a time. Add a repository or a local path in Projects, run a scan, then come back to see vulnerabilities, secrets and the fixed version that closes each finding."
      >
        <Link to="/projects" className={buttonVariants()}>
          Go to projects
        </Link>
      </EmptyState>
    )
  }

  const openFinding = findings.data?.find(
    (finding) => finding.fingerprint === openFingerprint,
  )
  const filtered = type !== '' || severity !== ''
  // Only rows still on screen count, so a filter change never acts on hidden findings.
  const checkedFindings = (findings.data ?? []).filter((finding) =>
    checked.has(finding.fingerprint),
  )
  const allChecked =
    findings.data !== undefined &&
    findings.data.length > 0 &&
    checkedFindings.length === findings.data.length

  function toggleChecked(fingerprint: string) {
    setChecked((current) => {
      const next = new Set(current)
      if (!next.delete(fingerprint)) next.add(fingerprint)
      return next
    })
  }

  return (
    <>
      <section
        aria-label="Report filters"
        className="flex flex-wrap items-end gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex w-64 flex-col gap-1">
          <label htmlFor="reports-asset" className="text-xs font-medium text-muted">
            Project
          </label>
          <select
            id="reports-asset"
            value={selected?.id ?? ''}
            onChange={(event) => {
              void navigate({
                to: '/security-reports',
                search: { asset: Number(event.target.value) },
                replace: true,
              })
              setOpenFingerprint(null)
            }}
            className={inputClass}
          >
            {assetList.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.display_name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex w-44 flex-col gap-1">
          <label htmlFor="reports-type" className="text-xs font-medium text-muted">
            Type
          </label>
          <select
            id="reports-type"
            value={type}
            onChange={(event) => {
              setType(event.target.value as FindingType | '')
              setOpenFingerprint(null)
            }}
            className={inputClass}
          >
            <option value="">All types</option>
            {typeOptions.map((option) => (
              <option key={option} value={option}>
                {typeLabels[option]}
              </option>
            ))}
          </select>
        </div>

        <div className="flex w-40 flex-col gap-1">
          <label htmlFor="reports-severity" className="text-xs font-medium text-muted">
            Severity
          </label>
          <select
            id="reports-severity"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value as Severity | '')
              setOpenFingerprint(null)
            }}
            className={inputClass}
          >
            <option value="">All severities</option>
            {severityOptions.map((option) => (
              <option key={option} value={option}>
                {option === 'unknown' ? 'Unknown' : capitalize(option)}
              </option>
            ))}
          </select>
        </div>

        <div className="flex w-36 flex-col gap-1">
          <label htmlFor="reports-status" className="text-xs font-medium text-muted">
            Status
          </label>
          <select
            id="reports-status"
            value={status}
            onChange={(event) => {
              setStatus(event.target.value as FindingStatus)
              setOpenFingerprint(null)
            }}
            className={inputClass}
          >
            <option value="open">Open</option>
            <option value="ignored">Ignored</option>
          </select>
        </div>

        <p className="ml-auto text-xs text-faint">
          Findings of {selected?.display_name ?? 'this project'}&rsquo;s latest
          succeeded scan
        </p>
      </section>

      {findings.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">Loading findings…</p>
        </section>
      ) : null}

      {findings.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[13px] font-semibold">Findings failed to load</h2>
          <ErrorNote error={findings.error} />
        </section>
      ) : null}

      {findings.isSuccess && findings.data.length === 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-8">
          <h2 className="text-[15px] font-semibold tracking-[-0.01em]">
            {status === 'open' && !filtered
              ? 'No open findings in the latest scan'
              : status === 'ignored' && !filtered
                ? 'No ignored findings in the latest scan'
                : 'No findings match these filters'}
          </h2>
          <p className="mt-2 max-w-[52ch] text-muted">
            {filtered || status === 'ignored'
              ? 'Clear a filter, or switch Status to Open to see the findings still waiting for a decision.'
              : 'Either the project has no succeeded scan yet, or its latest scan found nothing open. Run a scan from Projects, then reload this page.'}
          </p>
        </section>
      ) : null}

      {findings.isSuccess && findings.data.length > 0 ? (
        <section
          aria-labelledby="findings-heading"
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 id="findings-heading" className="text-[13px] font-semibold">
              Findings
            </h2>
            <span className="text-faint">
              {findings.data.length} in the latest succeeded scan
            </span>
          </div>
          {checkedFindings.length > 0 ? (
            <BulkBar
              key={status}
              findings={checkedFindings}
              status={status}
              onDone={() => setChecked(new Set())}
            />
          ) : null}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead className="text-xs text-faint">
                <tr>
                  <th className="w-6 pb-2">
                    <Checkbox
                      aria-label="Select all findings"
                      checked={allChecked}
                      indeterminate={checkedFindings.length > 0 && !allChecked}
                      onChange={() =>
                        setChecked(
                          allChecked
                            ? new Set()
                            : new Set(findings.data.map((finding) => finding.fingerprint)),
                        )
                      }
                    />
                  </th>
                  <th className="pb-2 pl-3 font-medium">Severity</th>
                  <th className="pb-2 pl-3 font-medium">Type</th>
                  <th className="pb-2 pl-3 font-medium">Rule</th>
                  <th className="pb-2 pl-3 font-medium">Package</th>
                  <th className="pb-2 pl-3 font-medium">Finding</th>
                  <th className="pb-2 pl-3 font-medium">Scanner</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {findings.data.map((finding) => (
                  <FindingRow
                    key={finding.fingerprint}
                    finding={finding}
                    checked={checked.has(finding.fingerprint)}
                    onCheck={() => toggleChecked(finding.fingerprint)}
                    onOpen={() => setOpenFingerprint(finding.fingerprint)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {openFinding ? (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          onClose={() => setOpenFingerprint(null)}
        />
      ) : null}
    </>
  )
}

/** FindingRow is one table row; the whole row opens the drawer. */
function FindingRow({
  finding,
  checked,
  onCheck,
  onOpen,
}: {
  finding: Finding
  checked: boolean
  onCheck: () => void
  onOpen: () => void
}) {
  const packageLabel =
    finding.package_name === undefined
      ? undefined
      : finding.package_version === undefined
        ? finding.package_name
        : `${finding.package_name}@${finding.package_version}`

  return (
    <tr
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onOpen()
        }
      }}
      className="cursor-pointer align-top hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
    >
      {/* The checkbox cell must not open the drawer. */}
      <td
        className="py-2"
        onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => event.stopPropagation()}
      >
        <Checkbox
          aria-label={`Select ${finding.title}`}
          checked={checked}
          onChange={onCheck}
        />
      </td>
      <td className="py-2 pr-3 pl-3">
        <Badge tone={severityTone[finding.severity]}>
          {finding.severity === 'unknown' ? 'unknown' : capitalize(finding.severity)}
        </Badge>
      </td>
      <td className="py-2 pl-3 whitespace-nowrap">
        {typeLabels[finding.type]}
        {finding.type === 'license' ? (
          <span className="ml-1.5 text-xs text-faint">informational</span>
        ) : null}
        {finding.status === 'ignored' ? (
          <span className="ml-1.5 text-xs text-faint">
            {finding.state ? stateLabels[finding.state].toLowerCase() : 'ignored'}
          </span>
        ) : null}
      </td>
      <td className="py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted">
        {finding.rule_id ?? '—'}
      </td>
      <td className="py-2 pl-3">
        {packageLabel ? (
          <span className="font-mono text-xs break-all">{packageLabel}</span>
        ) : null}
        {finding.fixed_version ? (
          <span className="block text-xs text-muted">
            fixed in <span className="font-mono">{finding.fixed_version}</span>
          </span>
        ) : finding.location ? (
          <span className="block truncate font-mono text-xs text-faint" title={finding.location}>
            {finding.location}
          </span>
        ) : null}
      </td>
      <td className="max-w-[38ch] py-2 pl-3">
        <span className="block">{finding.title}</span>
        {finding.occurrences > 1 ? (
          <span className="text-xs text-faint tabular-nums">
            ×{finding.occurrences} occurrences
          </span>
        ) : null}
      </td>
      <td className="py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted">
        {finding.scanner}
      </td>
    </tr>
  )
}

/**
 * FindingDrawer shows one finding's detail (§7.4). Scanner text is untrusted
 * (§4.3): the description is plain text and only https references become links.
 */
function FindingDrawer({
  finding,
  onClose,
}: {
  finding: Finding
  onClose: () => void
}) {
  const panel = useRef<HTMLDivElement>(null)
  const setState = useSetFindingState()
  const clearState = useClearFindingState()
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')

  // Focus moves into the drawer when it opens, so Escape and Tab work at once.
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null 
    panel.current?.focus()
    return () => {
      if (opener?.isConnected) opener.focus()
    }
  }, [])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setState.mutate(
      {
        asset_id: finding.asset_id,
        fingerprint: finding.fingerprint,
        state: decision,
        reason: reason.trim(),
      },
      { onSuccess: onClose },
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
                    clearState.mutate(
                      {
                        fingerprint: finding.fingerprint,
                        assetId: finding.asset_id,
                      },
                      { onSuccess: onClose },
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

/**
 * BulkBar acts on every checked finding at once: open findings get one shared
 * decision and reason, ignored findings can be reopened together.
 */
function BulkBar({
  findings,
  status,
  onDone,
}: {
  findings: Finding[]
  status: FindingStatus
  onDone: () => void
}) {
  const bulk = useBulkFindingState()
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')
  const count = findings.length
  const target = {
    assetId: findings[0].asset_id,
    fingerprints: findings.map((finding) => finding.fingerprint),
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    bulk.mutate(
      { ...target, decision: { state: decision, reason: reason.trim() } },
      { onSuccess: onDone },
    )
  }

  return (
    <div className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
      {status === 'open' ? (
        <form
          onSubmit={submit}
          aria-label="Bulk decision"
          className="flex flex-wrap items-center gap-2"
        >
          <span className="text-xs font-medium tabular-nums">{count} selected</span>
          <select
            aria-label="Hide selected findings as"
            value={decision}
            onChange={(event) => setDecision(event.target.value as FindingState)}
            className={cn(inputClass, 'w-40')}
          >
            <option value="ignored">Ignored</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="false_positive">False positive</option>
          </select>
          <input
            aria-label="Reason"
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Reason, shared by every selected finding"
            className={cn(inputClass, 'w-auto min-w-48 flex-1')}
          />
          <Button
            type="submit"
            size="sm"
            disabled={bulk.isPending || reason.trim() === ''}
          >
            {bulk.isPending ? 'Saving…' : `Hide ${count}`}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onDone}>
            Clear
          </Button>
        </form>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium tabular-nums">{count} selected</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={bulk.isPending}
            onClick={() => bulk.mutate(target, { onSuccess: onDone })}
          >
            {bulk.isPending ? 'Reopening…' : `Reopen ${count}`}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onDone}>
            Clear
          </Button>
        </div>
      )}
      {bulk.isError ? (
        <ErrorNote
          error={bulk.error}
          fix="Findings before the failure were saved; the list shows what is left."
        />
      ) : null}
    </div>
  )
}

/** Checkbox is a native checkbox that can also show the mixed (indeterminate) state. */
function Checkbox({
  indeterminate = false,
  ...props
}: Omit<ComponentProps<'input'>, 'type'> & { indeterminate?: boolean }) {
  return (
    <input
      type="checkbox"
      ref={(node) => {
        if (node) node.indeterminate = indeterminate
      }}
      className="size-3.5 cursor-pointer align-middle accent-accent"
      {...props}
    />
  )
}

/** ErrorNote shows the problem detail the API returned (§7). */
function ErrorNote({ error, fix }: { error: unknown; fix?: string }) {
  const cause =
    error instanceof ApiError
      ? `${error.message}${error.problem?.title ? ` (${error.problem.title})` : ''}`
      : error instanceof Error
        ? error.message
        : 'the request failed'

  return (
    <p role="alert" className="text-xs text-critical">
      {cause}{' '}
      <span className="text-muted">
        {fix ?? 'Reload the page; if it persists, check the terminal running bastion.'}
      </span>
    </p>
  )
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function trapTab(event: KeyboardEvent<HTMLElement>, container: HTMLElement){
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