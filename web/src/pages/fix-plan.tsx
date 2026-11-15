import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'

import type { Asset } from '../api/assets'
import { epssQuery } from '../api/epss'
import { latestFindingsQuery, type Finding } from '../api/findings'
import {
  fixPlanQuery,
  type FixPlanNoFix,
  type FixPlanStep,
} from '../api/fixplan'
import {
  DataTable,
  DataTableRow,
  type DataTableColumn,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { ErrorNote } from '../components/error-note'
import { FilterBar } from '../components/filter-bar'
import { FindingDrawer } from '../components/finding-drawer'
import { SeverityCountBadges } from '../components/severity-counts'
import { Badge } from '../components/ui/badge'
import { capitalize, severityTone } from '../lib/finding-labels'
import { epssLabel } from '../lib/epss'

/**
 * FixPlanPanel is §7.2's "Fix plan" tab: one project's open vulnerabilities
 * grouped by the package upgrade that closes them (#27). The endpoint is per
 * asset, so the project filter is the panel's first step.
 */
export function FixPlanPanel({
  assetList,
  selected,
}: {
  assetList: readonly Asset[]
  selected: Asset | undefined
}) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const [openFingerprint, setOpenFingerprint] = useState<string | null>(null)

  const plan = useQuery(fixPlanQuery(selected?.id))
  const epss = useQuery(epssQuery)
  // The plan carries finding ids; the list supplies the rows the drawer needs.
  const findings = useQuery({
    ...latestFindingsQuery({
      assetId: selected?.id,
      type: 'vulnerability',
      status: 'open',
    }),
    enabled: selected !== undefined,
  })

  function toggle(key: string) {
    setExpanded((current) => {
      const next = new Set(current)
      if (!next.delete(key)) next.add(key)
      return next
    })
  }

  const openFinding = findings.data?.find(
    (finding) => finding.fingerprint === openFingerprint,
  )

  return (
    <>
      <FilterBar
        label="Fix plan filters"
        fields={[
          {
            id: 'fix-plan-project',
            label: 'Project',
            value: selected === undefined ? '' : String(selected.id),
            className: 'w-64',
            options: [
              { value: '', label: 'Choose a project' },
              ...assetList.map((asset) => ({
                value: String(asset.id),
                label: asset.display_name,
              })),
            ],
            onChange: (value) => {
              setExpanded(new Set())
              setOpenFingerprint(null)
              void navigate({
                to: '/findings',
                search:
                  value === ''
                    ? { tab: 'fix-plan' }
                    : { tab: 'fix-plan', asset: Number(value) },
                replace: true,
              })
            },
          },
        ]}
      >
        <p className="ml-auto text-xs text-faint">
          {selected === undefined
            ? 'Grouped by the package upgrade that closes each finding'
            : `Open vulnerabilities of ${selected.display_name}’s latest succeeded scan`}
        </p>
      </FilterBar>

      {selected === undefined ? (
        <EmptyState
          title="Choose a project"
          body="A fix plan groups one project's open vulnerabilities by the package upgrade that closes them: upgrade lodash to 4.17.21 and three findings go away at once. Pick a project above to see its steps."
        />
      ) : null}

      {selected !== undefined && plan.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">Loading fix plan…</p>
        </section>
      ) : null}

      {selected !== undefined && plan.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[13px] font-semibold">Fix plan failed to load</h2>
          <ErrorNote error={plan.error} />
        </section>
      ) : null}

      {plan.isSuccess &&
      plan.data.steps.length === 0 &&
      plan.data.no_fix.length === 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-8">
          <h2 className="text-[15px] font-semibold tracking-[-0.01em]">
            No open vulnerabilities
          </h2>
          <p className="mt-2 max-w-[52ch] text-muted">
            The latest succeeded scan found nothing open in this project, so
            there is nothing to upgrade. Rescan the project from Repositories to
            refresh the plan.
          </p>
        </section>
      ) : null}

      {plan.isSuccess && plan.data.steps.length > 0 ? (
        <section
          aria-labelledby="fix-plan-heading"
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 id="fix-plan-heading" className="text-[13px] font-semibold">
              Fix plan
            </h2>
            <span className="text-faint">
              {plan.data.steps.length}{' '}
              {plan.data.steps.length === 1 ? 'upgrade' : 'upgrades'} close{' '}
              {plan.data.steps.reduce(
                (total, step) => total + step.finding_count,
                0,
              )}{' '}
              findings
            </span>
          </div>
          <PlanTable
            rows={plan.data.steps}
            columns={stepColumns(expanded, epss.data?.enabled === true)}
            rowKey={(step) => planRowKey('step', step.ecosystem, step.package)}
            expanded={expanded}
            onToggle={toggle}
            detail={(step) => (
              <FindingList
                ids={step.finding_ids}
                findings={findings.data}
                onOpen={setOpenFingerprint}
              />
            )}
          />
        </section>
      ) : null}

      {plan.isSuccess && plan.data.no_fix.length > 0 ? (
        <section
          aria-labelledby="fix-plan-no-fix-heading"
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2
              id="fix-plan-no-fix-heading"
              className="text-[13px] font-semibold"
            >
              No fix available
            </h2>
            <span className="text-faint">
              No fixed version is published for{' '}
              {plan.data.no_fix.length === 1 ? 'this package' : 'these packages'}
              , so an upgrade does not close the findings
            </span>
          </div>
          <PlanTable
            rows={plan.data.no_fix}
            columns={noFixColumns(expanded)}
            rowKey={(group) =>
              planRowKey('no-fix', group.ecosystem, group.package)
            }
            expanded={expanded}
            onToggle={toggle}
            detail={(group) => (
              <FindingList
                ids={group.finding_ids}
                findings={findings.data}
                onOpen={setOpenFingerprint}
              />
            )}
          />
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

/** planRowKey names a plan row: the step or no-fix group of one package. */
function planRowKey(prefix: string, ecosystem: string, pkg: string): string {
  return `${prefix}\u0000${ecosystem}\u0000${pkg}`
}

/** stepColumns is the fix plan row: the upgrade, its ecosystem and what it closes. */
function stepColumns(
  expanded: ReadonlySet<string>,
  showEPSS = false,
): DataTableColumn<FixPlanStep>[] {
  return [
    {
      id: 'upgrade',
      header: 'Upgrade',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (step) => (
        <span className="text-[13px]">
          Upgrade <span className="font-mono">{step.package}</span>{' '}
          <span className="font-mono text-muted">{installed(step)}</span>{' '}
          <span aria-hidden="true">→</span>{' '}
          <span className="font-mono font-medium">{step.target_version}</span>
          {step.approximate ? (
            <span
              className="ml-1.5 text-xs text-faint"
              title="No ecosystem-specific version comparison decided this target, so the version order is a best effort."
            >
              approximate
            </span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'ecosystem',
      header: 'Ecosystem',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 font-mono text-xs text-muted',
      cell: (step) => step.ecosystem,
    },
    ...(showEPSS
      ? [
          {
            id: 'epss',
            header: 'Max EPSS',
            headerClassName: 'pl-3',
            cellClassName: 'py-2 pl-3 whitespace-nowrap text-[13px] tabular-nums',
            cell: (step: FixPlanStep) =>
              step.max_epss ? (
                <span title={epssLabel(step.max_epss)}>
                  {step.max_epss.score.toFixed(2)}
                </span>
              ) : (
                <span className="text-faint">—</span>
              ),
          } satisfies DataTableColumn<FixPlanStep>,
        ]
      : []),
    {
      id: 'closes',
      header: 'Closes',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (step) => (
        <span className="flex items-center gap-2">
          <span className="text-[13px] tabular-nums">
            {step.finding_count}{' '}
            {step.finding_count === 1 ? 'finding' : 'findings'}
          </span>
          <SeverityCountBadges counts={step.severity_counts} />
        </span>
      ),
    },
    {
      id: 'details',
      header: '',
      headerClassName: 'pl-3',
      cellClassName:
        'py-2 pr-3 pl-3 text-right text-xs whitespace-nowrap text-muted',
      cell: (step) =>
        expanded.has(planRowKey('step', step.ecosystem, step.package))
          ? 'Hide findings'
          : `Show ${String(step.finding_count)}`,
    },
  ]
}

/** noFixColumns is the "No fix available" row: the package and its findings. */
function noFixColumns(
  expanded: ReadonlySet<string>,
): DataTableColumn<FixPlanNoFix>[] {
  return [
    {
      id: 'package',
      header: 'Package',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (group) => (
        <span className="text-[13px]">
          <span className="font-mono">{group.package || '—'}</span>{' '}
          <span className="font-mono text-xs text-muted">
            {group.ecosystem}
          </span>
        </span>
      ),
    },
    {
      id: 'closes',
      header: 'Findings',
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (group) => (
        <span className="flex items-center gap-2">
          <span className="text-[13px] tabular-nums">
            {group.finding_count}{' '}
            {group.finding_count === 1 ? 'finding' : 'findings'}
          </span>
          <SeverityCountBadges counts={group.severity_counts} />
        </span>
      ),
    },
    {
      id: 'details',
      header: '',
      headerClassName: 'pl-3',
      cellClassName:
        'py-2 pr-3 pl-3 text-right text-xs whitespace-nowrap text-muted',
      cell: (group) =>
        expanded.has(planRowKey('no-fix', group.ecosystem, group.package))
          ? 'Hide findings'
          : `Show ${String(group.finding_count)}`,
    },
  ]
}

/** installed joins the group's installed versions for the row sentence. */
function installed(step: FixPlanStep): string {
  return step.installed_versions.length > 0
    ? step.installed_versions.join(', ')
    : 'unknown version'
}

/**
 * PlanTable renders one expandable row per package. A row opens on click,
 * Enter or Space, and its findings sit in a detail row below it.
 */
function PlanTable<T>({
  rows,
  columns,
  rowKey,
  expanded,
  onToggle,
  detail,
}: {
  rows: readonly T[]
  columns: DataTableColumn<T>[]
  rowKey: (row: T) => string
  expanded: ReadonlySet<string>
  onToggle: (key: string) => void
  detail: (row: T) => ReactNode
}) {
  return (
    <DataTable
      rows={rows}
      columns={columns}
      rowKey={rowKey}
      renderRow={(row) => {
        const key = rowKey(row)
        const open = expanded.has(key)
        return (
          <>
            <DataTableRow onActivate={() => onToggle(key)}>
              {columns.map((column) => (
                <td
                  key={column.id}
                  className={column.cellClassName}
                  title={column.cellTitle?.(row)}
                >
                  {column.cell?.(row)}
                </td>
              ))}
            </DataTableRow>
            {open ? (
              <tr className="bg-bg">
                <td colSpan={columns.length}>{detail(row)}</td>
              </tr>
            ) : null}
          </>
        )
      }}
    />
  )
}

/**
 * FindingList expands one step into its findings; a finding opens the same
 * detail drawer the findings list uses.
 */
function FindingList({
  ids,
  findings,
  onOpen,
}: {
  ids: readonly number[]
  findings: readonly Finding[] | undefined
  onOpen: (fingerprint: string) => void
}) {
  if (findings === undefined) {
    return <p className="p-3 text-xs text-muted">Loading findings…</p>
  }
  const members = findings.filter((finding) => ids.includes(finding.id))
  if (members.length === 0) {
    return (
      <p className="p-3 text-xs text-muted">
        These findings are no longer in the latest scan.
      </p>
    )
  }
  return (
    <ul className="flex flex-col gap-0.5 p-2">
      {members.map((finding) => (
        <li key={finding.id}>
          <button
            type="button"
            onClick={() => onOpen(finding.fingerprint)}
            className="flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
          >
            <Badge tone={severityTone[finding.severity]}>
              {finding.severity === 'unknown'
                ? 'unknown'
                : capitalize(finding.severity)}
            </Badge>
            <span className="font-mono text-xs whitespace-nowrap text-muted">
              {finding.rule_id ?? '—'}
            </span>
            <span className="truncate text-[13px]">{finding.title}</span>
          </button>
        </li>
      ))}
    </ul>
  )
}
