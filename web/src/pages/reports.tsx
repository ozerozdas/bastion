import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { assetsQuery } from '../api/assets'
import {
  latestFindingsQuery,
  useBulkFindingState,
  type Finding,
  type FindingState,
  type FindingStatus,
  type FindingType,
  type Severity,
} from '../api/findings'
import {
  DataTable,
  useRowRemovalFocus,
  type DataTableColumn,
  type DataTableSelection,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { ErrorNote } from '../components/error-note'
import { FilterBar, type FilterField } from '../components/filter-bar'
import { FindingDrawer } from '../components/finding-drawer'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { capitalize, severityTone, stateLabels, typeLabels } from '../lib/finding-labels'
import { cn } from '../lib/utils'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

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

const findingColumns: DataTableColumn<Finding>[] = [
  {
    id: 'severity',
    header: 'Severity',
    headerClassName: 'pl-3',
    cellClassName: 'py-2 pr-3 pl-3',
    cell: (finding) => (
      <Badge tone={severityTone[finding.severity]}>
        {finding.severity === 'unknown' ? 'unknown' : capitalize(finding.severity)}
      </Badge>
    ),
  },
  {
    id: 'type',
    header: 'Type',
    headerClassName: 'pl-3',
    cellClassName: 'py-2 pl-3 whitespace-nowrap',
    cell: (finding) => (
      <>
        {typeLabels[finding.type]}
        {finding.type === 'license' ? (
          <span className="ml-1.5 text-xs text-faint">informational</span>
        ) : null}
        {finding.status === 'ignored' ? (
          <span className="ml-1.5 text-xs text-faint">
            {finding.state ? stateLabels[finding.state].toLowerCase() : 'ignored'}
          </span>
        ) : null}
      </>
    ),
  },
  {
    id: 'rule',
    header: 'Rule',
    headerClassName: 'pl-3',
    cellClassName: 'py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted',
    cell: (finding) => finding.rule_id ?? '—',
  },
  {
    id: 'package',
    header: 'Package',
    headerClassName: 'pl-3',
    cellClassName: 'py-2 pl-3',
    cell: (finding) => {
      const packageLabel =
        finding.package_name === undefined
          ? undefined
          : finding.package_version === undefined
            ? finding.package_name
            : `${finding.package_name}@${finding.package_version}`

      return (
        <>
          {packageLabel ? (
            <span className="font-mono text-xs break-all">{packageLabel}</span>
          ) : null}
          {finding.fixed_version ? (
            <span className="block text-xs text-muted">
              fixed in <span className="font-mono">{finding.fixed_version}</span>
            </span>
          ) : finding.location ? (
            <span
              className="block truncate font-mono text-xs text-faint"
              title={finding.location}
            >
              {finding.location}
            </span>
          ) : null}
        </>
      )
    },
  },
  {
    id: 'finding',
    header: 'Finding',
    headerClassName: 'pl-3',
    cellClassName: 'max-w-[38ch] py-2 pl-3',
    cell: (finding) => (
      <>
        <span className="block">{finding.title}</span>
        {finding.occurrences > 1 ? (
          <span className="text-xs text-faint tabular-nums">
            ×{finding.occurrences} occurrences
          </span>
        ) : null}
      </>
    ),
  },
  {
    id: 'scanner',
    header: 'Scanner',
    headerClassName: 'pl-3',
    cellClassName: 'py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted',
    cell: (finding) => finding.scanner,
  },
]

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
  const openedAt = useRef(0)
  const findingsHeading = useRef<HTMLHeadingElement>(null)

  const assetList = assets.data ?? []
  // The URL wins; otherwise the first project keeps the page useful on arrival.
  const selected = assetList.find((asset) => asset.id === search.asset) ?? assetList[0]

  // A removed project id must not stay in the URL: once the list has loaded,
  // point the URL at the project actually shown, as the select does.
  const selectedId = selected?.id
  useEffect(() => {
    if (search.asset === undefined || selectedId === undefined) return
    if (search.asset === selectedId) return
    void navigate({
      to: '/security-reports',
      search: { asset: selectedId },
      replace: true,
    })
  }, [navigate, search.asset, selectedId])

  const findings = useQuery({
    ...latestFindingsQuery({
      assetId: selected?.id,
      type: type === '' ? undefined : type,
      severity: severity === '' ? undefined : severity,
      status,
    }),
    enabled: selected !== undefined,
  })

  // A decision removes the row that opened the drawer, so the drawer's own
  // focus restore lands on nothing: keep focus in the table once the refreshed
  // list has dropped it (issue #75).
  const rowFocus = useRowRemovalFocus({
    rows: findings.data,
    rowKey: (finding) => finding.fingerprint,
    fallback: findingsHeading,
    onRemoved: () => setOpenFingerprint(null),
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

  const filters: FilterField[] = [
    {
      id: 'reports-asset',
      label: 'Project',
      value: selected?.id === undefined ? '' : String(selected.id),
      className: 'w-64',
      options: assetList.map((asset) => ({
        value: String(asset.id),
        label: asset.display_name,
      })),
      onChange: (value) => {
        void navigate({
          to: '/security-reports',
          search: { asset: Number(value) },
          replace: true,
        })
        setOpenFingerprint(null)
      },
    },
    {
      id: 'reports-type',
      label: 'Type',
      value: type,
      className: 'w-44',
      options: [
        { value: '', label: 'All types' },
        ...typeOptions.map((option) => ({ value: option, label: typeLabels[option] })),
      ],
      onChange: (value) => {
        setType(value as FindingType | '')
        setOpenFingerprint(null)
      },
    },
    {
      id: 'reports-severity',
      label: 'Severity',
      value: severity,
      className: 'w-40',
      options: [
        { value: '', label: 'All severities' },
        ...severityOptions.map((option) => ({
          value: option,
          label: option === 'unknown' ? 'Unknown' : capitalize(option),
        })),
      ],
      onChange: (value) => {
        setSeverity(value as Severity | '')
        setOpenFingerprint(null)
      },
    },
    {
      id: 'reports-status',
      label: 'Status',
      value: status,
      className: 'w-36',
      options: [
        { value: 'open', label: 'Open' },
        { value: 'ignored', label: 'Ignored' },
      ],
      onChange: (value) => {
        setStatus(value as FindingStatus)
        setOpenFingerprint(null)
      },
    },
  ]

  const selection: DataTableSelection<Finding> = {
    all: {
      checked: allChecked,
      indeterminate: checkedFindings.length > 0 && !allChecked,
      onChange: () =>
        setChecked(
          allChecked
            ? new Set()
            : new Set((findings.data ?? []).map((finding) => finding.fingerprint)),
        ),
      label: 'Select all findings',
      checkboxClassName: 'cursor-pointer align-middle',
    },
    row: (finding) => ({
      checked: checked.has(finding.fingerprint),
      onChange: () => toggleChecked(finding.fingerprint),
      label: `Select ${finding.title}`,
      cellClassName: 'py-2',
      checkboxClassName: 'cursor-pointer align-middle',
    }),
    headerClassName: 'w-6',
  }

  return (
    <>
      <FilterBar label="Report filters" fields={filters}>
        <p className="ml-auto text-xs text-faint">
          Findings of {selected?.display_name ?? 'this project'}&rsquo;s latest
          succeeded scan
        </p>
      </FilterBar>

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
          <h2
            ref={findingsHeading}
            tabIndex={-1}
            className="text-[15px] font-semibold tracking-[-0.01em]"
          >
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
            <h2
              ref={findingsHeading}
              id="findings-heading"
              tabIndex={-1}
              className="text-[13px] font-semibold"
            >
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
          <DataTable
            rows={findings.data}
            columns={findingColumns}
            rowKey={(finding) => finding.fingerprint}
            selection={selection}
            onRowActivate={(finding, index) => {
              openedAt.current = index
              setOpenFingerprint(finding.fingerprint)
            }}
            bodyRef={rowFocus.bodyRef}
          />
        </section>
      ) : null}

      {openFinding ? (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          onClose={() => setOpenFingerprint(null)}
          onRemoving={() =>
            rowFocus.beginRemoval(openFinding.fingerprint, openedAt.current)
          }
          onRemoveFailed={rowFocus.cancelRemoval}
        />
      ) : null}
    </>
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
