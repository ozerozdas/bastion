import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'

import type { Asset } from '../api/assets'
import { ApiError } from '../api/client'
import { epssQuery } from '../api/epss'
import { allFindingsQuery, type Finding } from '../api/findings'
import {
  fixPlanQuery,
  useOpenFixPlanPullRequest,
  type FixPlanFactor,
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
import { SeverityCountBadges } from '../components/severity-counts'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { severityLabel, severityTone } from '../lib/finding-labels'
import { epssLabel } from '../lib/epss'
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
}: {
  assetList: readonly Asset[]
  selected: Asset | undefined
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
  const epss = useQuery(epssQuery)
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

  return (
    <>
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
        <p className="ml-auto text-xs text-faint">
          {selected === undefined
            ? t('fixPlan.scope.grouped')
            : t('fixPlan.scope.one', { project: selected.display_name })}
        </p>
      </FilterBar>

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

      {plan.isSuccess && plan.data.steps.length > 0 ? (
        <section
          aria-labelledby="fix-plan-heading"
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 id="fix-plan-heading" className="text-[0.8125rem] font-semibold">
              {t('fixPlan.title')}
            </h2>
            <span className="text-faint">
              {t('fixPlan.summary', {
                count: plan.data.steps.length,
                upgrades: plan.data.steps.length,
                findings: plan.data.steps.reduce(
                  (total, step) => total + step.finding_count,
                  0,
                ),
              })}
            </span>
          </div>
          <PlanTable
            rows={plan.data.steps}
            columns={stepColumns(
              expanded,
              epss.data?.enabled === true,
              canOpenPullRequest ? setPrStep : undefined,
            )}
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
              className="text-[0.8125rem] font-semibold"
            >
              {t('fixPlan.noFix.title')}
            </h2>
            <span className="text-faint">
              {t('fixPlan.noFix.subtitle', {
                count: plan.data.no_fix.length,
              })}
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

/** stepColumns is the fix plan row: the upgrade, its ecosystem and what it closes. */
function stepColumns(
  expanded: ReadonlySet<string>,
  showEPSS = false,
  onOpenPullRequest?: (step: FixPlanStep) => void,
): DataTableColumn<FixPlanStep>[] {
  return [
    {
      id: 'score',
      header: t('fixPlan.column.score'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 align-top whitespace-nowrap',
      cell: (step) => (
        <span className="flex flex-col gap-0.5">
          <span className="text-[0.8125rem] font-medium tabular-nums">
            {Math.round(step.score)}
          </span>
          <span className="text-[0.6875rem] text-faint" title={scoreTitle(step)}>
            {scoreFactors(step.factors)}
          </span>
        </span>
      ),
    },
    {
      id: 'upgrade',
      header: t('fixPlan.column.upgrade'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (step) => (
        <span className="text-[0.8125rem]">
          {t('fixPlan.upgrade')} <span className="font-mono">{step.package}</span>{' '}
          <span className="font-mono text-muted">{installed(step)}</span>{' '}
          <span aria-hidden="true">→</span>{' '}
          <span className="font-mono font-medium">{step.target_version}</span>
          {step.approximate ? (
            <span
              className="ml-1.5 text-xs text-faint"
              title={t('fixPlan.approximateTitle')}
            >
              {t('fixPlan.approximate')}
            </span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'ecosystem',
      header: t('fixPlan.column.ecosystem'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 font-mono text-xs text-muted',
      cell: (step) => step.ecosystem,
    },
    ...(showEPSS
      ? [
          {
            id: 'epss',
            header: t('fixPlan.column.maxEpss'),
            headerClassName: 'pl-3',
            cellClassName: 'py-2 pl-3 whitespace-nowrap text-[0.8125rem] tabular-nums',
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
      header: t('fixPlan.column.closes'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (step) => (
        <span className="flex items-center gap-2">
          <span className="text-[0.8125rem] tabular-nums">
            {t('fixPlan.findingCount', { count: step.finding_count })}
          </span>
          <SeverityCountBadges counts={step.severity_counts} />
        </span>
      ),
    },
    ...(onOpenPullRequest !== undefined
      ? [
          {
            id: 'pull-request',
            header: '',
            headerClassName: 'pl-3',
            cellClassName: 'py-2 pl-3 text-right whitespace-nowrap',
            cell: (step: FixPlanStep) => <StepPullRequestAction step={step} onOpen={onOpenPullRequest} />,
          } satisfies DataTableColumn<FixPlanStep>,
        ]
      : []),
    {
      id: 'details',
      header: '',
      headerClassName: 'pl-3',
      cellClassName:
        'py-2 pr-3 pl-3 text-right text-xs whitespace-nowrap text-muted',
      cell: (step) =>
        expanded.has(planRowKey('step', step.ecosystem, step.package))
          ? t('fixPlan.hide')
          : t('fixPlan.show', { count: step.finding_count }),
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
      header: t('fixPlan.column.package'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (group) => (
        <span className="text-[0.8125rem]">
          <span className="font-mono">{group.package || '—'}</span>{' '}
          <span className="font-mono text-xs text-muted">
            {group.ecosystem}
          </span>
        </span>
      ),
    },
    {
      id: 'closes',
      header: t('fixPlan.column.findings'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      cell: (group) => (
        <span className="flex items-center gap-2">
          <span className="text-[0.8125rem] tabular-nums">
            {t('fixPlan.findingCount', { count: group.finding_count })}
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
          ? t('fixPlan.hide')
          : t('fixPlan.show', { count: group.finding_count }),
    },
  ]
}

/** installed joins the group's installed versions for the row sentence. */
function installed(step: FixPlanStep): string {
  return step.installed_versions.length > 0
    ? step.installed_versions.join(', ')
    : t('fixPlan.unknownVersion')
}

/** scoreFactors is the one-line explanation next to a step's score. */
function scoreFactors(factors: readonly FixPlanFactor[]): string {
  return factors.map(scoreFactor).join(' × ')
}

/**
 * scoreFactor labels one factor the way the row reads: "severity 17 × EPSS 4.2
 * × latest image 1.5". A factor that does not apply says so in words instead
 * of printing its 1x multiplier.
 */
function scoreFactor(factor: FixPlanFactor): string {
  switch (factor.name) {
    case 'severity':
      return t('fixPlan.factor.severity', {
        value: Math.round(factor.value),
      })
    case 'epss':
      return factor.value > 1
        ? t('fixPlan.factor.epss', { value: factor.value.toFixed(1) })
        : factor.detail
    case 'latest_image':
      return factor.value > 1
        ? t('fixPlan.factor.latestImage', { value: factor.value.toFixed(1) })
        : factor.detail
    case 'reachability':
      return factor.value === 1
        ? factor.detail
        : t('fixPlan.factor.reachability', { detail: factor.detail })
    default:
      return t('fixPlan.factor.other', {
        name: factor.name,
        value: factor.value,
      })
  }
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
