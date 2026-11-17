import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'

import { assetsQuery } from '../api/assets'
import { epssQuery } from '../api/epss'
import { reachabilityQuery } from '../api/reachability'
import {
  exportFindingsUrl,
  latestFindingsQuery,
  useBulkFindingState,
  type Finding,
  type FindingFilter,
  type FindingGroup,
  type FindingState,
  type FindingStatus,
  type FindingType,
  type FindingsExportFormat,
  type FindingsExportView,
  type Severity,
} from '../api/findings'
import {
  DataTable,
  useRowRemovalFocus,
  type DataTableColumn,
  type DataTableSelection,
  type DataTableSort,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { ErrorNote } from '../components/error-note'
import { FilterBar, type FilterField } from '../components/filter-bar'
import { FindingDrawer } from '../components/finding-drawer'
import { GroupDrawer } from '../components/group-drawer'
import { LicencePolicyCard } from '../components/licence-policy-card'
import { Pager } from '../components/pager'
import { PageActions } from '../components/app-shell'
import { Tabs } from '../components/ui/tabs'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { severityLabel, severityTone, stateLabels, typeLabels } from '../lib/finding-labels'
import { expiryDate, expiryValue, type ExpiryChoice } from '../lib/expiry'
import { epssLabel, percentileLabel } from '../lib/epss'
import { formatNumber, t, useLanguage, useT } from '../lib/i18n'
import {
  defaultFindingsPageSize,
  type FindingsPageSize,
  type FindingsSearch,
  type FindingsSort,
  type FindingsView,
} from '../lib/urls'
import { cn } from '../lib/utils'
import { FixPlanPanel } from './fix-plan'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'

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

/**
 * findingColumns builds the table for the projects on screen. The Project
 * column needs the asset names, which the findings themselves do not carry.
 * The scan diff page (#17) shows the same columns for its three groups.
 */
export function findingColumns(
  assetNames: ReadonlyMap<number, string>,
  showEPSS = false,
  showReachability = false,
): DataTableColumn<Finding>[] {
  const projectName = (finding: Finding) =>
    assetNames.get(finding.asset_id) ??
    t('asset.fallback', { id: finding.asset_id })

  return [
    {
      id: 'severity',
      header: t('findings.column.severity'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pr-3 pl-3',
      sortable: true,
      defaultSortDirection: 'desc',
      cell: (finding) => (
        <Badge tone={severityTone[finding.severity]}>
          {severityLabel(finding.severity)}
        </Badge>
      ),
    },
    ...(showEPSS
      ? [
          {
            id: 'epss',
            header: t('findings.column.epss'),
            headerClassName: 'pl-3',
            cellClassName:
              'py-2 pl-3 whitespace-nowrap tabular-nums text-[0.8125rem]',
            cell: (finding: Finding) =>
              finding.epss ? (
                <span title={epssLabel(finding.epss)}>
                  {formatNumber(finding.epss.score, {
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2,
                  })}
                  <span className="ml-1 text-xs text-faint">
                    {percentileLabel(finding.epss.percentile * 100)}
                  </span>
                </span>
              ) : (
                <span className="text-faint">—</span>
              ),
          } satisfies DataTableColumn<Finding>,
        ]
      : []),
    ...(showReachability
      ? [
          {
            id: 'reachability',
            header: t('findings.column.reach'),
            headerClassName: 'pl-3',
            cellClassName: 'py-2 pl-3 whitespace-nowrap',
            cell: (finding: Finding) =>
              finding.reachability ? (
                <Badge
                  tone={
                    finding.reachability === 'reachable'
                      ? 'critical'
                      : finding.reachability === 'unreachable'
                        ? 'ok'
                        : 'neutral'
                  }
                >
                  {t(`reachability.${finding.reachability}`)}
                </Badge>
              ) : (
                <span className="text-faint">—</span>
              ),
          } satisfies DataTableColumn<Finding>,
        ]
      : []),
    {
      id: 'project',
      header: t('findings.column.project'),
      headerClassName: 'pl-3',
      cellClassName: 'max-w-[22ch] py-2 pl-3',
      sortable: true,
      cellTitle: projectName,
      cell: (finding) => (
        <span className="block truncate">{projectName(finding)}</span>
      ),
    },
    {
      id: 'type',
      header: t('findings.column.type'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 whitespace-nowrap',
      sortable: true,
      cell: (finding) => (
        <>
          {t(typeLabels[finding.type])}
          {finding.type === 'license' ? (
            <span className="ml-1.5 text-xs text-faint">
              {finding.licence_policy === 'deny'
                ? t('findings.licence.denied')
                : t('findings.licence.informational')}
            </span>
          ) : null}
          {finding.expired ? (
            <span className="ml-1.5 text-xs text-faint">
              {t('findings.decisionExpired')}
            </span>
          ) : finding.status === 'ignored' ? (
            <span className="ml-1.5 text-xs text-faint">
              {t(
                finding.state
                  ? stateLabels[finding.state]
                  : 'state.ignored',
              ).toLowerCase()}
            </span>
          ) : null}
        </>
      ),
    },
    {
      id: 'rule',
      header: t('findings.column.rule'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted',
      cell: (finding) => finding.rule_id ?? '—',
    },
    {
      id: 'package',
      header: t('findings.column.package'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3',
      sortable: true,
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
                {t('findings.fixedIn')}{' '}
                <span className="font-mono">{finding.fixed_version}</span>
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
      header: t('findings.column.finding'),
      headerClassName: 'pl-3',
      cellClassName: 'max-w-[38ch] py-2 pl-3',
      sortable: true,
      sortKey: 'title',
      cell: (finding) => (
        <>
          <span className="block">{finding.title}</span>
          {finding.occurrences > 1 ? (
            <span className="text-xs text-faint tabular-nums">
              {t('findings.occurrences', { count: finding.occurrences })}
            </span>
          ) : null}
        </>
      ),
    },
    {
      id: 'scanner',
      header: t('findings.column.scanner'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 font-mono text-xs whitespace-nowrap text-muted',
      cell: (finding) => finding.scanner,
    },
  ]
}

/**
 * groupedColumns builds the table for one row per rule and type (#90): the
 * worst severity, the rule, how many projects it reaches and the fix. The rows
 * come from the API's grouped view, so grouping is server-side.
 */
function groupedColumns(
  assetNames: ReadonlyMap<number, string>,
): DataTableColumn<FindingGroup>[] {
  const projects = (group: FindingGroup) =>
    t('findings.group.projects', { count: group.project_count })

  return [
    {
      id: 'severity',
      header: t('findings.column.severity'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pr-3 pl-3 whitespace-nowrap',
      sortable: true,
      defaultSortDirection: 'desc',
      cell: (group) => (
        <Badge tone={severityTone[group.severity]}>
          {severityLabel(group.severity)}
        </Badge>
      ),
    },
    {
      id: 'rule',
      header: t('findings.column.finding'),
      headerClassName: 'pl-3',
      cellClassName: 'max-w-[46ch] py-2 pl-3',
      sortable: true,
      sortKey: 'title',
      cell: (group) => (
        <>
          <span className="block">{group.title}</span>
          <span className="font-mono text-xs text-muted">
            {group.rule_id ??
              t('findings.group.findingFallback', {
                type: t(typeLabels[group.type]),
              })}
          </span>
        </>
      ),
    },
    {
      id: 'projects',
      header: t('findings.column.projects'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 whitespace-nowrap',
      sortable: true,
      sortKey: 'project',
      defaultSortDirection: 'desc',
      cellTitle: (group) =>
        group.asset_ids
          .map(
            (id) => assetNames.get(id) ?? t('asset.fallback', { id }),
          )
          .join(', '),
      cell: (group) => <span className="tabular-nums">{projects(group)}</span>,
    },
    {
      id: 'fixed',
      header: t('findings.column.fixedIn'),
      headerClassName: 'pl-3',
      cellClassName: 'py-2 pl-3 font-mono text-xs whitespace-nowrap',
      cellTitle: (group) =>
        group.fixed_versions.length > 1
          ? group.fixed_versions.join(', ')
          : undefined,
      cell: (group) =>
        group.fixed_version !== undefined ? (
          group.fixed_version
        ) : group.fixed_versions.length > 1 ? (
          <span className="text-muted">{t('findings.group.varies')}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ]
}

/**
 * exportFormats is the Export menu: the three formats the endpoint writes.
 */
const exportFormats: { format: FindingsExportFormat; label: string }[] = [
  { format: 'csv', label: 'CSV' },
  { format: 'xlsx', label: 'XLSX' },
  { format: 'json', label: 'JSON' },
]

/**
 * FindingsExportMenu is the Findings page action: it downloads the current
 * filters and view. The links are plain same-origin anchors, so the session
 * cookie authenticates the request and the server names the file.
 */
function FindingsExportMenu({
  filter,
  view,
}: {
  filter: FindingFilter
  view: FindingsExportView
}) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const menu = useRef<HTMLDivElement>(null)

  // A menu closes on an outside click or Escape, like every other popover.
  useEffect(() => {
    if (!open) return
    function closeOnPointer(event: MouseEvent) {
      if (menu.current !== null && !menu.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    function closeOnKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', closeOnPointer)
    document.addEventListener('keydown', closeOnKey)
    return () => {
      document.removeEventListener('mousedown', closeOnPointer)
      document.removeEventListener('keydown', closeOnKey)
    }
  }, [open])

  return (
    <div ref={menu} className="relative">
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        {t('findings.export')}
      </Button>
      {open ? (
        <div
          role="menu"
          aria-label={t('findings.export.aria')}
          className="absolute right-0 z-20 mt-1 flex w-28 flex-col rounded-md border border-border-strong bg-surface p-1 shadow-lg"
        >
          {exportFormats.map(({ format, label }) => (
            <a
              key={format}
              role="menuitem"
              href={exportFindingsUrl({ ...filter, format, view })}
              download
              onClick={() => setOpen(false)}
              className="rounded px-2 py-1 text-[0.8125rem] text-muted hover:bg-hover hover:text-fg"
            >
              {label}
            </a>
          ))}
        </div>
      ) : null}
    </div>
  )
}

/**
 * FindingsPage is §7.4: findings of every project, or of one when the Project
 * filter is set, with a detail drawer shared across projects. Grouped, one row
 * per rule across projects, is the default (#90, #106); a project filter
 * forces single, and the toggle only appears for the fleet-wide list.
 */
export function FindingsPage() {
  const t = useT()
  const languageCode = useLanguage()
  const search = useSearch({ from: '/findings' })
  const navigate = useNavigate()
  const assets = useQuery(assetsQuery)
  const epss = useQuery(epssQuery)
  const reachability = useQuery(reachabilityQuery)
  const tab = search.tab ?? 'findings'

  // Grouped is the default (#106); a project filter forces single, because
  // grouping exists to fold the same rule across projects.
  const grouped = search.asset === undefined && search.view !== 'single'
  const [type, setType] = useState<FindingType | ''>('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<FindingStatus>('open')
  const [openFingerprint, setOpenFingerprint] = useState<string | null>(null)
  const [openGroupKey, setOpenGroupKey] = useState<string | null>(null)
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())
  const [checkedGroups, setCheckedGroups] = useState<ReadonlySet<string>>(
    new Set(),
  )
  const openedAt = useRef(0)
  const openedGroupAt = useRef(0)
  const findingsHeading = useRef<HTMLHeadingElement>(null)

  // The view lives in the URL, so switching keeps the project filter and the
  // other way round. Grouped is the default, so only single is written.

  const assetList = useMemo(() => assets.data ?? [], [assets.data])
  // No project in the URL means every project: the list is fleet-wide unless
  // the Project filter narrows it.
  const selected =
    search.asset === undefined
      ? undefined
      : assetList.find((asset) => asset.id === search.asset)

  // A stale project id must not stay in the URL. With no id meaning "all
  // projects", an unknown id falls back to that instead of an arbitrary project.
  useEffect(() => {
    if (search.asset === undefined || assets.data === undefined) return
    if (assets.data.some((asset) => asset.id === search.asset)) return
    void navigate({
      to: '/findings',
      search: search.tab === 'fix-plan' ? { tab: 'fix-plan' } : {},
      replace: true,
    })
  }, [assets.data, navigate, search.asset, search.tab])

  const page = search.page ?? 1
  const pageSize = search.size ?? defaultFindingsPageSize
  // The URL owns the sort, so a reload or a shared link keeps it.
  const sortState: DataTableSort | undefined =
    search.sort === undefined
      ? undefined
      : { columnId: search.sort, direction: search.order ?? 'asc' }

  const findings = useQuery({
    ...latestFindingsQuery({
      assetId: selected?.id,
      type: type === '' ? undefined : type,
      severity: severity === '' ? undefined : severity,
      status,
      view: grouped ? 'grouped' : 'single',
      limit: pageSize,
      offset: (page - 1) * pageSize,
      sort: search.sort,
      order: search.order,
    }),
    // While the project list loads, a URL with an id may still name a project
    // that exists; asking for all findings first would be the wrong question.
    enabled:
      tab === 'findings' &&
      (search.asset === undefined || assets.isSuccess),
  })
  const list = findings.data
  // The API pages server-side, so only the current page's rows are here.
  const pageFindings = list?.findings
  const groups = list?.groups
  const total = list?.total ?? 0
  const totalFindings = list?.total_findings ?? 0

  const assetNames = useMemo(
    () => new Map(assetList.map((asset) => [asset.id, asset.display_name])),
    [assetList],
  )
  const columns = useMemo(
    () =>
      findingColumns(
        assetNames,
        epss.data?.enabled === true,
        reachability.data?.enabled === true,
      ),
    // The headers and fallbacks are translated, so a language switch rebuilds.
    [assetNames, epss.data?.enabled, reachability.data?.enabled, languageCode],
  )
  const groupColumns = useMemo(
    () => groupedColumns(assetNames),
    [assetNames, languageCode],
  )

  // A decision removes the row that opened the drawer, so the drawer's own
  // focus restore lands on nothing: keep focus in the table once the refreshed
  // list has dropped it (issue #75).
  const rowFocus = useRowRemovalFocus({
    rows: pageFindings,
    rowKey: (finding) => finding.fingerprint,
    fallback: findingsHeading,
    onRemoved: () => setOpenFingerprint(null),
  })
  // Grouped rows can disappear the same way when every member is hidden.
  const groupFocus = useRowRemovalFocus({
    rows: groups,
    rowKey: (group) => group.key,
    fallback: findingsHeading,
    onRemoved: () => setOpenGroupKey(null),
  })

  // A live refresh or a decision can empty the page the URL points at; go to
  // the last page instead of showing an empty table.
  useEffect(() => {
    if (list === undefined || list.total === 0 || page <= 1) return
    const lastPage = Math.max(1, Math.ceil(list.total / pageSize))
    if (page <= lastPage) return
    void navigate({
      to: '/findings',
      search: pageSearch({ page: lastPage, size: pageSize }),
      replace: true,
    })
    // pageSearch is rebuilt every render; the params it reads are the deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list, page, pageSize, navigate, search.asset, search.view, search.size])

  if (assets.isPending) {
    return (
      <section className="rounded-card border border-border-subtle bg-surface p-4">
        <p className="text-muted">{t('findings.loading')}</p>
      </section>
    )
  }

  if (assets.isError) {
    return (
      <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
        <h2 className="text-[0.8125rem] font-semibold">
          {t('findings.assetsFailed')}
        </h2>
        <ErrorNote error={assets.error} />
      </section>
    )
  }

  if (assetList.length === 0) {
    return (
      <EmptyState
        title={t('findings.empty.title')}
        body={t('findings.empty.body')}
      >
        <Link to="/repositories" className={buttonVariants()}>
          {t('findings.empty.action')}
        </Link>
      </EmptyState>
    )
  }

  // Grouped rows carry their members, so a member opened from the group drawer
  // is found there; single view reads the page's own findings.
  const openFinding = (
    grouped ? groups?.flatMap((group) => group.findings) : pageFindings
  )?.find((finding) => finding.fingerprint === openFingerprint)
  const openGroup = groups?.find((group) => group.key === openGroupKey)
  const filtered = type !== '' || severity !== ''
  // Grouped mode selects groups; a group stands for every member finding, so
  // the bulk bar and the drawer act on all of them across projects.
  const checkedGroupRows = (groups ?? []).filter((group) =>
    checkedGroups.has(group.key),
  )
  // Only rows on the current page count, so select-all never acts on a hidden
  // page and a filter change never acts on hidden findings.
  const checkedFindings = grouped
    ? checkedGroupRows.flatMap((group) => group.findings)
    : (pageFindings ?? []).filter((finding) => checked.has(finding.fingerprint))
  const allChecked =
    pageFindings !== undefined &&
    pageFindings.length > 0 &&
    checkedFindings.length === pageFindings.length
  const allGroupsChecked =
    groups !== undefined &&
    groups.length > 0 &&
    checkedGroupRows.length === groups.length

  function clearSelection() {
    setOpenFingerprint(null)
    setOpenGroupKey(null)
    setChecked(new Set())
    setCheckedGroups(new Set())
  }

  function toggleChecked(fingerprint: string) {
    setChecked((current) => {
      const next = new Set(current)
      if (!next.delete(fingerprint)) next.add(fingerprint)
      return next
    })
  }

  function toggleGroupChecked(key: string) {
    setCheckedGroups((current) => {
      const next = new Set(current)
      if (!next.delete(key)) next.add(key)
      return next
    })
  }

  // pageSearch keeps the view, project and page size while the page itself is
  // replaced; page 1 and the default size stay out of the URL.
  function pageSearch(next: {
    page?: number
    size?: FindingsPageSize
    sort?: DataTableSort
  }): FindingsSearch {
    const size = next.size ?? search.size
    const sort = next.sort ?? sortState
    return {
      ...(search.view === undefined ? {} : { view: search.view }),
      ...(search.asset === undefined ? {} : { asset: search.asset }),
      ...(size === undefined || size === defaultFindingsPageSize
        ? {}
        : { size }),
      ...(next.page === undefined || next.page <= 1
        ? {}
        : { page: next.page }),
      ...(sort === undefined
        ? {}
        : { sort: sort.columnId as FindingsSort }),
      ...(sort?.direction === 'desc' ? { order: 'desc' as const } : {}),
    }
  }

  function changePage(next: number) {
    void navigate({
      to: '/findings',
      search: pageSearch({ page: next, size: pageSize }),
      replace: true,
    })
    clearSelection()
  }

  function changePageSize(size: FindingsPageSize) {
    void navigate({
      to: '/findings',
      search: pageSearch({ size }),
      replace: true,
    })
    clearSelection()
  }

  // A new sort goes back to page 1: the old page may not exist in the new order.
  function changeSort(next: DataTableSort) {
    void navigate({
      to: '/findings',
      search: pageSearch({ sort: next }),
      replace: true,
    })
    clearSelection()
  }

  // A filter change goes back to page 1, so the list never opens on a page the
  // new result set does not have.
  function resetPage() {
    if (search.page === undefined) return
    void navigate({
      to: '/findings',
      search: pageSearch({ size: pageSize }),
      replace: true,
    })
  }

  function setView(next: FindingsView) {
    void navigate({
      to: '/findings',
      search: {
        ...(next === 'single' ? { view: 'single' as const } : {}),
        ...(search.size === undefined ? {} : { size: search.size }),
        ...(search.sort === undefined ? {} : { sort: search.sort }),
        ...(search.order === undefined ? {} : { order: search.order }),
      },
      replace: true,
    })
    clearSelection()
  }

  // The URL owns the tab, so a reload or a copied link lands on it; switching
  // keeps the project filter, because the plan is per asset.
  function changeTab(next: 'findings' | 'fix-plan') {
    void navigate({
      to: '/findings',
      search:
        next === 'fix-plan'
          ? {
              tab: 'fix-plan',
              ...(search.asset === undefined ? {} : { asset: search.asset }),
            }
          : {
              ...(search.asset === undefined ? {} : { asset: search.asset }),
              ...(search.size === undefined ? {} : { size: search.size }),
              ...(search.sort === undefined ? {} : { sort: search.sort }),
              ...(search.order === undefined ? {} : { order: search.order }),
            },
      replace: true,
    })
    clearSelection()
  }

  const filters: FilterField[] = [
    {
      id: 'findings-project',
      label: t('findings.filter.project'),
      value: selected === undefined ? '' : String(selected.id),
      className: 'w-64',
      options: [
        { value: '', label: t('findings.filter.allProjects') },
        ...assetList.map((asset) => ({
          value: String(asset.id),
          label: asset.display_name,
        })),
      ],
      onChange: (value) => {
        // A project filter forces single, so the view leaves the URL with it.
        void navigate({
          to: '/findings',
          search: {
            ...(value === '' ? {} : { asset: Number(value) }),
            ...(search.size === undefined ? {} : { size: search.size }),
            ...(search.sort === undefined ? {} : { sort: search.sort }),
            ...(search.order === undefined ? {} : { order: search.order }),
          },
          replace: true,
        })
        clearSelection()
      },
    },
    {
      id: 'findings-type',
      label: t('findings.filter.type'),
      value: type,
      className: 'w-44',
      options: [
        { value: '', label: t('findings.filter.allTypes') },
        ...typeOptions.map((option) => ({
          value: option,
          label: t(typeLabels[option]),
        })),
      ],
      onChange: (value) => {
        setType(value as FindingType | '')
        resetPage()
        setOpenFingerprint(null)
        setOpenGroupKey(null)
        setChecked(new Set())
        setCheckedGroups(new Set())
      },
    },
    {
      id: 'findings-severity',
      label: t('findings.filter.severity'),
      value: severity,
      className: 'w-40',
      options: [
        { value: '', label: t('findings.filter.allSeverities') },
        ...severityOptions.map((option) => ({
          value: option,
          label: severityLabel(option),
        })),
      ],
      onChange: (value) => {
        setSeverity(value as Severity | '')
        resetPage()
        setOpenFingerprint(null)
        setOpenGroupKey(null)
        setChecked(new Set())
        setCheckedGroups(new Set())
      },
    },
    {
      id: 'findings-status',
      label: t('findings.filter.status'),
      value: status,
      className: 'w-36',
      options: [
        { value: 'open', label: t('findings.filter.open') },
        { value: 'ignored', label: t('findings.filter.ignored') },
      ],
      onChange: (value) => {
        setStatus(value as FindingStatus)
        resetPage()
        setOpenFingerprint(null)
        setOpenGroupKey(null)
        setChecked(new Set())
        setCheckedGroups(new Set())
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
            : new Set((pageFindings ?? []).map((finding) => finding.fingerprint)),
        ),
      label: t('findings.selectAll'),
      checkboxClassName: 'cursor-pointer align-middle',
    },
    row: (finding) => ({
      checked: checked.has(finding.fingerprint),
      onChange: () => toggleChecked(finding.fingerprint),
      label: t('findings.selectRow', { title: finding.title }),
      cellClassName: 'py-2',
      checkboxClassName: 'cursor-pointer align-middle',
    }),
    headerClassName: 'w-6',
  }

  const groupSelection: DataTableSelection<FindingGroup> = {
    all: {
      checked: allGroupsChecked,
      indeterminate: checkedGroupRows.length > 0 && !allGroupsChecked,
      onChange: () =>
        setCheckedGroups(
          allGroupsChecked
            ? new Set()
            : new Set((groups ?? []).map((group) => group.key)),
        ),
      label: t('findings.selectAllGroups'),
      checkboxClassName: 'cursor-pointer align-middle',
    },
    row: (group) => ({
      checked: checkedGroups.has(group.key),
      onChange: () => toggleGroupChecked(group.key),
      label: t('findings.selectGroupRow', { title: group.title }),
      cellClassName: 'py-2',
      checkboxClassName: 'cursor-pointer align-middle',
    }),
    headerClassName: 'w-6',
  }

  return (
    <>
      {tab === 'findings' ? (
        <PageActions>
          <FindingsExportMenu
            filter={{
              assetId: selected?.id,
              type: type === '' ? undefined : type,
              severity: severity === '' ? undefined : severity,
              status,
            }}
            view={grouped ? 'grouped' : 'single'}
          />
        </PageActions>
      ) : null}
      <Tabs
        label={t('findings.tabs.aria')}
        items={[
          { value: 'findings', label: t('findings.tabs.findings') },
          { value: 'fix-plan', label: t('findings.tabs.fixPlan') },
        ]}
        value={tab}
        onChange={changeTab}
      >
        {tab === 'fix-plan' ? (
          <FixPlanPanel assetList={assetList} selected={selected} />
        ) : (
          <>
      {selected === undefined ? null : (
        <LicencePolicyCard
          assetId={selected.id}
          title={t('licence.forProject', { project: selected.display_name })}
        />
      )}
      <FilterBar label={t('findings.filter.aria')} fields={filters}>
        {/* Grouping folds a rule across projects, so it is only offered while
            every project is in the list (#106). */}
        {search.asset === undefined ? (
          <div
            role="group"
            aria-label={t('findings.view.aria')}
            className="flex items-center gap-1 rounded-md border border-border-subtle bg-bg p-0.5"
          >
            {(['single', 'grouped'] as const).map((option) => {
              const active = grouped === (option === 'grouped')
              return (
                <button
                  key={option}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setView(option)}
                  className={cn(
                    'rounded px-2.5 py-1 text-[0.8125rem] transition-colors',
                    active
                      ? 'bg-surface text-fg shadow-sm'
                      : 'text-muted hover:text-fg',
                  )}
                >
                  {option === 'single'
                    ? t('findings.view.single')
                    : t('findings.view.grouped')}
                </button>
              )
            })}
          </div>
        ) : null}
        <p className="ml-auto text-xs text-faint">
          {selected === undefined
            ? t('findings.scope.all')
            : t('findings.scope.one', { project: selected.display_name })}
        </p>
      </FilterBar>

      {findings.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('findings.loading')}</p>
        </section>
      ) : null}

      {findings.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('findings.failed')}
          </h2>
          <ErrorNote error={findings.error} />
        </section>
      ) : null}

      {list !== undefined && total === 0 ? (
        <section className="rounded-card border border-border-subtle bg-surface p-8">
          <h2
            ref={findingsHeading}
            tabIndex={-1}
            className="text-[0.9375rem] font-semibold tracking-[-0.01em]"
          >
            {status === 'open' && !filtered
              ? t('findings.emptyOpen', {
                  count: selected === undefined ? 2 : 1,
                })
              : status === 'ignored' && !filtered
                ? t('findings.emptyIgnored', {
                    count: selected === undefined ? 2 : 1,
                  })
                : t('findings.emptyFiltered')}
          </h2>
          <p className="mt-2 max-w-[52ch] text-muted">
            {filtered || status === 'ignored'
              ? t('findings.emptyHint.filtered')
              : selected === undefined
                ? t('findings.emptyHint.all')
                : t('findings.emptyHint.one')}
          </p>
        </section>
      ) : null}

      {list !== undefined && total > 0 ? (
        <section
          aria-labelledby="findings-heading"
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2
              ref={findingsHeading}
              id="findings-heading"
              tabIndex={-1}
              className="text-[0.8125rem] font-semibold"
            >
              {t('findings.heading')}
            </h2>
            <span className="text-faint">
              {grouped
                ? t('findings.count.grouped', {
                    total: formatNumber(total),
                    findings: formatNumber(totalFindings),
                  })
                : selected === undefined
                  ? t('findings.count.all', { total: formatNumber(total) })
                  : t('findings.count.one', { total: formatNumber(total) })}
            </span>
          </div>
          {checkedFindings.length > 0 ? (
            <BulkBar
              key={`${status}-${String(grouped)}`}
              findings={checkedFindings}
              status={status}
              onDone={() => {
                setChecked(new Set())
                setCheckedGroups(new Set())
              }}
            />
          ) : null}
          {grouped ? (
            <DataTable
              rows={groups ?? []}
              columns={groupColumns}
              rowKey={(group) => group.key}
              selection={groupSelection}
              sort={sortState}
              onSortChange={changeSort}
              onRowActivate={(group, index) => {
                openedGroupAt.current = index
                setOpenGroupKey(group.key)
              }}
              bodyRef={groupFocus.bodyRef}
            />
          ) : (
            <DataTable
              rows={pageFindings ?? []}
              columns={columns}
              rowKey={(finding) => finding.fingerprint}
              selection={selection}
              sort={sortState}
              onSortChange={changeSort}
              onRowActivate={(finding, index) => {
                openedAt.current = index
                setOpenFingerprint(finding.fingerprint)
              }}
              bodyRef={rowFocus.bodyRef}
            />
          )}
          <Pager
            total={total}
            page={page}
            pageSize={pageSize}
            onPageChange={changePage}
            onPageSizeChange={changePageSize}
          />
        </section>
      ) : null}

      {openGroup ? (
        <GroupDrawer
          key={openGroup.key}
          group={openGroup}
          assetNames={assetNames}
          onClose={() => setOpenGroupKey(null)}
          onRemoving={() =>
            groupFocus.beginRemoval(openGroup.key, openedGroupAt.current)
          }
          onRemoveFailed={groupFocus.cancelRemoval}
          onOpenFinding={(finding) => {
            setOpenGroupKey(null)
            setOpenFingerprint(finding.fingerprint)
          }}
        />
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
        )}
      </Tabs>
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
  const t = useT()
  const bulk = useBulkFindingState()
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')
  const [expiryChoice, setExpiryChoice] = useState<ExpiryChoice>('none')
  const [expiryDay, setExpiryDay] = useState('')
  const count = findings.length
  // A selection can span projects, and a decision is keyed on
  // (asset_id, fingerprint), so each finding keeps its own asset id.
  const target = findings.map((finding) => ({
    assetId: finding.asset_id,
    fingerprint: finding.fingerprint,
  }))

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    bulk.mutate(
      {
        findings: target,
        decision: {
          state: decision,
          reason: reason.trim(),
          expires_at: expiryValue(expiryChoice, expiryDay),
        },
      },
      { onSuccess: onDone },
    )
  }

  return (
    <div className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
      {status === 'open' ? (
        <form
          onSubmit={submit}
          aria-label={t('findings.bulk.aria')}
          className="flex flex-wrap items-center gap-2"
        >
          <span className="text-xs font-medium tabular-nums">
            {t('findings.bulk.selected', { count })}
          </span>
          <select
            aria-label={t('findings.bulk.hideAs')}
            value={decision}
            onChange={(event) => setDecision(event.target.value as FindingState)}
            className={cn(inputClass, 'w-40')}
          >
            <option value="ignored">{t('state.ignored')}</option>
            <option value="accepted_risk">{t('state.accepted_risk')}</option>
            <option value="false_positive">
              {t('state.false_positive')}
            </option>
          </select>
          <select
            aria-label={t('findings.bulk.expires')}
            value={expiryChoice}
            onChange={(event) => setExpiryChoice(event.target.value as ExpiryChoice)}
            className={cn(inputClass, 'w-36')}
          >
            <option value="none">{t('findings.bulk.noExpiry')}</option>
            <option value="30">{t('findings.bulk.in30')}</option>
            <option value="90">{t('findings.bulk.in90')}</option>
            <option value="date">{t('findings.bulk.pickDate')}</option>
          </select>
          {expiryChoice === 'date' ? (
            <input
              type="date"
              aria-label={t('findings.bulk.expiryDate')}
              required
              min={expiryDate(0)}
              value={expiryDay}
              onChange={(event) => setExpiryDay(event.target.value)}
              className={cn(inputClass, 'w-40')}
            />
          ) : null}
          <input
            aria-label={t('findings.bulk.reason')}
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={t('findings.bulk.reasonPlaceholder')}
            className={cn(inputClass, 'w-auto min-w-48 flex-1')}
          />
          <Button
            type="submit"
            size="sm"
            disabled={bulk.isPending || reason.trim() === ''}
          >
            {bulk.isPending
              ? t('findings.bulk.saving')
              : t('findings.bulk.hide', { count })}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onDone}>
            {t('findings.bulk.clear')}
          </Button>
        </form>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium tabular-nums">
            {t('findings.bulk.selected', { count })}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={bulk.isPending}
            onClick={() => bulk.mutate({ findings: target }, { onSuccess: onDone })}
          >
            {bulk.isPending
              ? t('findings.bulk.reopening')
              : t('findings.bulk.reopen', { count })}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onDone}>
            {t('findings.bulk.clear')}
          </Button>
        </div>
      )}
      {bulk.isError ? (
        <ErrorNote
          error={bulk.error}
          fix={t('findings.bulk.fix')}
        />
      ) : null}
    </div>
  )
}
