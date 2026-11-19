import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'

import type { Asset } from '../api/assets'
import { ApiError } from '../api/client'
import { allFindingsQuery, type Finding } from '../api/findings'
import {
  fixPlanQuery,
  useOpenFixPlanPullRequest,
  type FixPlanNoFix,
  type FixPlanPullRequestRequest,
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
import { useDrawerFocus } from '../components/drawer-focus'
import { OpenSeverityCounts } from '../components/severity-counts'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { severityLabel, severityTone } from '../lib/finding-labels'
import { t, useT } from '../lib/i18n'
import { manifestPath } from '../lib/manifests'

/**
 * FixPlanPanel is §7.2's "Fix plan" tab: one project's open vulnerabilities
 * grouped by the package upgrade that closes them (#27). The endpoint is per
 * asset, so the project filter is the panel's first step.
 */
export function FixPlanPanel({
  assetList,
  selected,
  pinned = false,
}: {
  assetList: readonly Asset[]
  selected: Asset | undefined
  /** pinned hides the project picker: the page's path already names the project. */
  pinned?: boolean
}) {
  const t = useT()
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const [openFingerprint, setOpenFingerprint] = useState<string | null>(null)
  // The step whose pull request dialog is open. Only a repository asset with a
  // GitHub connection can open one (#47).
  const [prStep, setPrStep] = useState<FixPlanStep | null>(null)
  const canOpenPullRequest =
    selected?.kind === 'repo' && selected.connection_id !== undefined

  const plan = useQuery(fixPlanQuery(selected?.id))
  // The plan carries finding ids; the list supplies the rows the drawer needs.
  const findings = useQuery({
    ...allFindingsQuery({ assetId: selected?.id, type: 'vulnerability', status: 'open' }),
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

  const steps = plan.data?.steps ?? []
  const noFix = plan.data?.no_fix ?? []

  return (
    <>
      {pinned ? null : (
      <FilterBar
        label={t('fixPlan.filter.aria')}
        fields={[
          {
            id: 'fix-plan-project',
            label: t('fixPlan.filter.project'),
            value: selected === undefined ? '' : String(selected.id),
            className: 'w-64',
            options: [
              { value: '', label: t('fixPlan.choose') },
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
        {selected === undefined ? (
          <p className="ml-auto text-xs text-faint">{t('fixPlan.scope.grouped')}</p>
        ) : null}
      </FilterBar>
      )}

      {selected === undefined ? (
        <EmptyState
          title={t('fixPlan.choose.title')}
          body={t('fixPlan.choose.body')}
        />
      ) : null}

      {selected !== undefined && plan.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('fixPlan.loading')}</p>
        </section>
      ) : null}

      {selected !== undefined && plan.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('fixPlan.failed')}
          </h2>
          <ErrorNote error={plan.error} />
        </section>
      ) : null}

      {plan.isSuccess &&
      plan.data.steps.length === 0 &&
      plan.data.no_fix.length === 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-8">
          <h2 className="text-[0.9375rem] font-semibold tracking-[-0.01em]">
            {t('fixPlan.empty.title')}
          </h2>
          <p className="mt-2 max-w-[52ch] text-muted">
            {t('fixPlan.empty.body')}
          </p>
        </section>
      ) : null}

      {/* The upgrades and the packages without a fix are two halves of one
          answer, so they share a card. */}
      {selected !== undefined && (steps.length > 0 || noFix.length > 0) ? (
        <div className="flex flex-col gap-4 rounded-card border border-border-subtle bg-surface p-4">
          <div className="flex flex-col gap-1">
            <div className="flex flex-wrap items-baseline gap-2.5">
              <h2
                id="fix-plan-heading"
                className="text-[0.9375rem] font-semibold"
              >
                {t('fixPlan.title')}
              </h2>
              {steps.length > 0 ? (
                <span className="text-xs text-muted">
                  {t('fixPlan.summary', {
                    count: steps.length,
                    upgrades: steps.length,
                    findings: steps.reduce(
                      (total, step) => total + step.finding_count,
                      0,
                    ),
                  })}
                </span>
              ) : null}
            </div>
            <p className="text-xs text-faint">
              {t('fixPlan.scope.one', { project: selected.display_name })}
            </p>
          </div>
      {steps.length > 0 ? (
        <section
          aria-labelledby="fix-plan-heading"
          className="flex flex-col gap-3"
        >
          <PlanTable
            rows={steps}
            columns={stepColumns(expanded, toggle, canOpenPullRequest ? setPrStep : undefined)}
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

      {noFix.length > 0 ? (
        <section
          aria-labelledby="fix-plan-no-fix-heading"
          className={
            steps.length > 0
              ? 'flex flex-col gap-3 border-t border-border-subtle pt-4'
              : 'flex flex-col gap-3'
          }
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2
              id="fix-plan-no-fix-heading"
              className="text-[0.8125rem] font-semibold"
            >
              {t('fixPlan.noFix.title')}
            </h2>
            <span className="text-faint">
              {t('fixPlan.noFix.subtitle', {
                count: noFix.length,
              })}
            </span>
          </div>
          <PlanTable
            rows={noFix}
            columns={noFixColumns(expanded, toggle)}
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
        </div>
      ) : null}

      {openFinding ? (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          onClose={() => setOpenFingerprint(null)}
        />
      ) : null}

      {prStep !== null && selected !== undefined ? (
        <PullRequestDialog
          asset={selected}
          step={prStep}
          findings={findings.data}
          onClose={() => setPrStep(null)}
        />
      ) : null}
    </>
  )
}

/** planRowKey names a plan row: the step or no-fix group of one package. */
function planRowKey(prefix: string, ecosystem: string, pkg: string): string {
  return `${prefix}\u0000${ecosystem}\u0000${pkg}`
}

/** cellClass keeps every plan cell on one line, aligned to the row's middle. */
const cellClass = 'py-2 pl-3 align-middle whitespace-nowrap'

/** packageCell is a package's name with its ecosystem and approximate marker. */
function packageCell(
  pkg: string,
  ecosystem: string,
  approximate = false,
): ReactNode {
  return (
    <span className="flex items-center gap-1.5 whitespace-nowrap">
      <span
        className="max-w-[24ch] truncate font-mono text-[0.8125rem] font-medium"
        title={pkg}
      >
        {pkg || '—'}
      </span>
      <Badge>{ecosystem}</Badge>
      {approximate ? (
        <Badge title={t('fixPlan.approximateTitle')}>
          {t('fixPlan.approximate')}
        </Badge>
      ) : null}
    </span>
  )
}

/**
 * upgradeCell is the compact "from → target": the installed version (or the
 * first one, with a +N chip for the rest) and the target in an ok badge. Every
 * installed version stays in the tooltip.
 */
function upgradeCell(step: FixPlanStep): ReactNode {
  const versions = step.installed_versions
  const first = versions[0]
  const rest = versions.length - 1
  const all = versions.length > 0 ? versions.join(', ') : t('fixPlan.unknownVersion')
  return (
    <span
      className="flex items-center gap-1.5 font-mono text-[0.8125rem]"
      title={all}
    >
      <span className="text-muted">{first ?? t('fixPlan.unknownVersion')}</span>
      {rest > 0 ? (
        <span
          className="rounded border border-border-subtle px-1 text-[0.6875rem] whitespace-nowrap text-muted"
          title={all}
        >
          +{rest}
        </span>
      ) : null}
      <span aria-hidden="true" className="text-faint">
        →
      </span>
      <Badge tone="ok" className="font-mono">
        {step.target_version}
      </Badge>
    </span>
  )
}

/** closesCell is the finding count and the severity mix on one line. */
function closesCell(
  count: number,
  counts: FixPlanStep['severity_counts'],
): ReactNode {
  return (
    <span className="flex items-center gap-2 whitespace-nowrap">
      <span className="text-[0.8125rem] tabular-nums">
        {t('fixPlan.findingCount', { count })}
      </span>
      <OpenSeverityCounts counts={counts} />
    </span>
  )
}

/** ExpandAction toggles the findings under a plan row without opening the row. */
function ExpandAction({
  open,
  count,
  onToggle,
}: {
  open: boolean
  count: number
  onToggle: () => void
}) {
  const t = useT()
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation()
        onToggle()
      }}
      onKeyDown={(event) => event.stopPropagation()}
      className="rounded px-1.5 py-0.5 text-xs whitespace-nowrap text-muted hover:bg-hover hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
    >
      {open ? t('fixPlan.hide') : t('fixPlan.show', { count })}
    </button>
  )
}

/** stepColumns is the fix plan row: package, upgrade, what it closes, score and actions. */
function stepColumns(
  expanded: ReadonlySet<string>,
  onToggle: (key: string) => void,
  onOpenPullRequest?: (step: FixPlanStep) => void,
): DataTableColumn<FixPlanStep>[] {
  return [
    {
      id: 'package',
      header: t('fixPlan.column.package'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: (step) =>
        packageCell(step.package, step.ecosystem, step.approximate),
    },
    {
      id: 'upgrade',
      header: t('fixPlan.column.upgrade'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: (step) => upgradeCell(step),
    },
    {
      id: 'closes',
      header: t('fixPlan.column.closes'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: (step) => closesCell(step.finding_count, step.severity_counts),
    },
    {
      id: 'score',
      header: t('fixPlan.column.score'),
      headerClassName: 'pl-3',
      cellClassName: `${cellClass} tabular-nums`,
      cell: (step) => (
        <span
          className="text-[0.8125rem] font-medium"
          title={scoreTitle(step)}
        >
          {Math.round(step.score)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: t('fixPlan.column.actions'),
      headerClassName: 'pl-3 pr-3 text-right',
      cellClassName: 'py-2 pr-3 pl-3 align-middle text-right',
      cell: (step) => {
        const key = planRowKey('step', step.ecosystem, step.package)
        return (
          <span className="flex items-center justify-end gap-1.5 whitespace-nowrap">
            {onOpenPullRequest === undefined ? null : (
              <StepPullRequestAction step={step} onOpen={onOpenPullRequest} />
            )}
            <ExpandAction
              open={expanded.has(key)}
              count={step.finding_count}
              onToggle={() => onToggle(key)}
            />
          </span>
        )
      },
    },
  ]
}

/** noFixColumns keeps the plan's columns aligned: package, dashes, closes, actions. */
function noFixColumns(
  expanded: ReadonlySet<string>,
  onToggle: (key: string) => void,
): DataTableColumn<FixPlanNoFix>[] {
  return [
    {
      id: 'package',
      header: t('fixPlan.column.package'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: (group) => packageCell(group.package, group.ecosystem),
    },
    {
      id: 'upgrade',
      header: t('fixPlan.column.upgrade'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: () => <span className="text-faint">—</span>,
    },
    {
      id: 'closes',
      header: t('fixPlan.column.closes'),
      headerClassName: 'pl-3',
      cellClassName: cellClass,
      cell: (group) => closesCell(group.finding_count, group.severity_counts),
    },
    {
      id: 'score',
      header: t('fixPlan.column.score'),
      headerClassName: 'pl-3',
      cellClassName: `${cellClass} tabular-nums`,
      cell: () => <span className="text-faint">—</span>,
    },
    {
      id: 'actions',
      header: t('fixPlan.column.actions'),
      headerClassName: 'pl-3 pr-3 text-right',
      cellClassName: 'py-2 pr-3 pl-3 align-middle text-right',
      cell: (group) => {
        const key = planRowKey('no-fix', group.ecosystem, group.package)
        return (
          <span className="flex items-center justify-end gap-1.5 whitespace-nowrap">
            <ExpandAction
              open={expanded.has(key)}
              count={group.finding_count}
              onToggle={() => onToggle(key)}
            />
          </span>
        )
      },
    },
  ]
}

/** installed joins the group's installed versions for the pull request dialog. */
function installed(step: FixPlanStep): string {
  return step.installed_versions.length > 0
    ? step.installed_versions.join(', ')
    : t('fixPlan.unknownVersion')
}

/** scoreTitle spells out every factor with its detail for the tooltip. */
function scoreTitle(step: FixPlanStep): string {
  const lines = step.factors.map((factor) =>
    t('fixPlan.factorTitle', {
      name: factor.name,
      value: factor.value.toFixed(2),
      detail: factor.detail,
    }),
  )
  return [t('fixPlan.scoreTitle', { score: step.score.toFixed(2) }), ...lines].join(
    '\n',
  )
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
    return <p className="p-3 text-xs text-muted">{t('fixPlan.findingList.loading')}</p>
  }
  const members = findings.filter((finding) => ids.includes(finding.id))
  if (members.length === 0) {
    return (
      <p className="p-3 text-xs text-muted">
        {t('fixPlan.findingList.gone')}
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
              {severityLabel(finding.severity)}
            </Badge>
            <span className="font-mono text-xs whitespace-nowrap text-muted">
              {finding.rule_id ?? '—'}
            </span>
            <span className="truncate text-[0.8125rem]">{finding.title}</span>
          </button>
        </li>
      ))}
    </ul>
  )
}

/**
 * StepPullRequestAction is the step's pull request state: a link once one is
 * recorded (#47), the action otherwise. A merged pull request never offers the
 * action again; the next scan is what confirms the bump.
 */
function StepPullRequestAction({
  step,
  onOpen,
}: {
  step: FixPlanStep
  onOpen: (step: FixPlanStep) => void
}) {
  const t = useT()
  const pullRequest = step.pull_request
  if (pullRequest !== undefined) {
    return (
      <a
        href={pullRequest.url}
        target="_blank"
        rel="noreferrer"
        onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => event.stopPropagation()}
        className="text-xs whitespace-nowrap underline"
      >
        {pullRequest.state === 'merged'
          ? t('fixPlan.pr.mergedLink', { number: pullRequest.number })
          : t('fixPlan.pr.openLink', { number: pullRequest.number })}
      </a>
    )
  }
  if (manifestEcosystem(step.ecosystem) === undefined) return null
  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={(event) => {
        // The row opens its findings on click; the action must not.
        event.stopPropagation()
        onOpen(step)
      }}
      onKeyDown={(event) => event.stopPropagation()}
    >
      {t('fixPlan.pr.action')}
    </Button>
  )
}

/** manifestEcosystem narrows a step's ecosystem to the manifests #47 edits. */
function manifestEcosystem(
  ecosystem: string,
): FixPlanPullRequestRequest['ecosystem'] | undefined {
  return ecosystem === 'go' || ecosystem === 'npm' ? ecosystem : undefined
}

/** manifestForStep is the manifest the dialog names, from the step's findings. */
function manifestForStep(
  step: FixPlanStep,
  findings: readonly Finding[] | undefined,
): string | undefined {
  const ids = new Set(step.finding_ids)
  for (const finding of findings ?? []) {
    if (!ids.has(finding.id) || finding.package_name !== step.package) continue
    const path = manifestPath(step.ecosystem, finding.location)
    if (path !== undefined) return path
  }
  return undefined
}

/**
 * PullRequestDialog is the confirmation #47 requires: it names the package, the
 * upgrade, the manifest and what bastion will do on GitHub, and no request is
 * sent until the user confirms.
 */
function PullRequestDialog({
  asset,
  step,
  findings,
  onClose,
}: {
  asset: Asset
  step: FixPlanStep
  findings: readonly Finding[] | undefined
  onClose: () => void
}) {
  const t = useT()
  const { panel, onKeyDown } = useDrawerFocus(onClose)
  const open = useOpenFixPlanPullRequest(asset.id)

  const ecosystem = manifestEcosystem(step.ecosystem)
  const manifest = manifestForStep(step, findings)

  function confirm() {
    if (ecosystem === undefined) return
    open.mutate({
      ecosystem,
      package: step.package,
      target: step.target_version,
      confirm: true,
    })
  }

  const conflictURL =
    open.error instanceof ApiError &&
    typeof open.error.problem?.pr_url === 'string'
      ? open.error.problem.pr_url
      : undefined

  return (
    <div className="fixed inset-0 z-40">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="absolute inset-0 overlay-scrim"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="fix-plan-pr-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="absolute inset-x-4 top-[12vh] mx-auto flex max-h-[76vh] max-w-[520px] flex-col gap-4 overflow-y-auto rounded-xl border border-border-subtle bg-surface p-5 shadow-xl focus:outline-none"
      >
        <h2 id="fix-plan-pr-title" className="text-[0.9375rem] font-semibold">
          {t('fixPlan.pr.title')}
        </h2>

        {open.isSuccess ? (
          <>
            <p className="text-[0.8125rem] text-muted">
              {t('fixPlan.pr.opened', { number: open.data.number })}
            </p>
            <p className="font-mono text-xs text-muted">
              {t('fixPlan.pr.changed', { manifest: open.data.manifest })}
            </p>
            <a
              href={open.data.url}
              target="_blank"
              rel="noreferrer"
              className="truncate font-mono text-xs text-fg underline"
            >
              {open.data.url}
            </a>
            <div className="flex justify-end">
              <Button type="button" onClick={onClose}>
                {t('common.close')}
              </Button>
            </div>
          </>
        ) : (
          <>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[0.8125rem]">
              <dt className="text-muted">{t('fixPlan.pr.package')}</dt>
              <dd className="font-mono">{step.package}</dd>
              <dt className="text-muted">{t('fixPlan.pr.upgrade')}</dt>
              <dd>
                <span className="font-mono text-muted">{installed(step)}</span>{' '}
                <span aria-hidden="true">→</span>{' '}
                <span className="font-mono font-medium">
                  {step.target_version}
                </span>
              </dd>
              <dt className="text-muted">{t('fixPlan.pr.manifest')}</dt>
              <dd className="font-mono">
                {manifest ?? t('fixPlan.pr.manifestUnknown')}
              </dd>
            </dl>

            <p className="text-xs text-muted">{t('fixPlan.pr.branch')}</p>
            <p className="text-xs text-muted">{t('fixPlan.pr.lockfile')}</p>

            {open.isError ? (
              <div className="flex flex-col gap-1">
                <ErrorNote error={open.error} />
                {conflictURL !== undefined ? (
                  <a
                    href={conflictURL}
                    target="_blank"
                    rel="noreferrer"
                    className="truncate font-mono text-xs underline"
                  >
                    {conflictURL}
                  </a>
                ) : null}
              </div>
            ) : null}

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={open.isPending}
              >
                {t('common.cancel')}
              </Button>
              <Button type="button" onClick={confirm} disabled={open.isPending}>
                {open.isPending
                  ? t('fixPlan.pr.opening')
                  : t('fixPlan.pr.confirm')}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
