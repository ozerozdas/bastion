/** isHttpsUrl allows a reference to become a link only over https (§4.3). */
export function isHttpsUrl(value: string): boolean {
  return value.trim().toLowerCase().startsWith('https://')
}

/** AssetSearch is the Findings route's optional project filter. */
export type AssetSearch = {
  asset?: number
}

/**
 * parseAssetSearch reads ?asset=<id> from a route's search params. A missing or
 * malformed id is dropped, so /findings?asset=abc lists every project rather
 * than failing. The two branches keep the validation the old reports route had.
 */
export function parseAssetSearch(search: Record<string, unknown>): AssetSearch {
  const raw = search.asset
  if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) {
    return { asset: raw }
  }
  if (typeof raw === 'string' && /^\d+$/.test(raw)) {
    return { asset: Number(raw) }
  }
  return {}
}

/** reportTrendDays are the windows the trend report offers. */
export const reportTrendDays = [30, 90, 180, 365] as const

/** ReportTrendDays is one offered trend window, in days. */
export type ReportTrendDays = (typeof reportTrendDays)[number]

/** ReportSearch is a report page's scope: project, advisory and trend window. */
export type ReportSearch = {
  /** Narrows the report to one project; absent means the whole fleet. */
  asset?: number
  /** ?cve=<id> is the advisory the CVE insights report looks up. */
  cve?: string
  /** ?days=<n> is the trend window; absent is the API's 90-day default. */
  days?: ReportTrendDays
}

/** MaxCveSearchLength caps the advisory id, so a pasted blob cannot fill the URL. */
const maxCveSearchLength = 64

/**
 * parseReportSearch reads ?asset=<id>, ?cve=<id> and ?days=<n> from a report
 * page. Malformed values are dropped, so a shared link with a stale window
 * still opens the report instead of failing the route.
 */
export function parseReportSearch(
  search: Record<string, unknown>,
): ReportSearch {
  const cve =
    typeof search.cve === 'string'
      ? [...search.cve.trim()].slice(0, maxCveSearchLength).join('')
      : ''
  const days = reportTrendDays.find(
    (option) => String(option) === String(search.days),
  )
  return {
    ...parseAssetSearch(search),
    ...(cve === '' ? {} : { cve }),
    ...(days === undefined ? {} : { days }),
  }
}

/** SortOrder is the direction of a server-side sort. */
export type SortOrder = 'asc' | 'desc'

/** FindingsSort is a column the API can order the latest findings by. */
export type FindingsSort = 'severity' | 'title' | 'package' | 'project' | 'type'

const findingsSortColumns: readonly FindingsSort[] = [
  'severity',
  'title',
  'package',
  'project',
  'type',
]

/** ScanSort is a column the API can order the scan list by. */
export type ScanSort = 'started' | 'status' | 'project' | 'duration' | 'findings'

const scanSortColumns: readonly ScanSort[] = [
  'started',
  'status',
  'project',
  'duration',
  'findings',
]

/** parseSortColumn keeps only a column the API's sort enum accepts. */
function parseSortColumn<T extends string>(
  raw: unknown,
  columns: readonly T[],
): T | undefined {
  if (typeof raw !== 'string') return undefined
  return columns.find((column) => column === raw)
}

/** parseSortOrder keeps descending; ascending is the canonical default. */
function parseSortOrder(raw: unknown): SortOrder | undefined {
  return raw === 'desc' ? 'desc' : undefined
}

/** FindingsView names the two ways the Findings page lists rows (#90). */
export type FindingsView = 'single' | 'grouped'

/** FindingsPageSizes are the page sizes the Findings table offers. */
export const findingsPageSizes = [25, 50, 100, 200] as const

/** FindingsPageSize is one of the offered page sizes. */
export type FindingsPageSize = (typeof findingsPageSizes)[number]

/** defaultFindingsPageSize is the page size when the URL names none. */
export const defaultFindingsPageSize: FindingsPageSize = 50

/**
 * FindingsSearch is the Findings route's search params. Grouped is the default
 * (#106), so it is the bare path; only opting out into single is in the URL.
 */
export type FindingsSearch = {
  /** ?view=single shows one row per finding; absent means grouped. */
  view?: 'single'
  /**
   * Narrows the list to one project; absent means every project. Grouping
   * spans projects, so a project filter forces single and the view is ignored.
   */
  asset?: number
  /** ?tab=fix-plan shows the package upgrade plan; absent is the findings list. */
  tab?: 'fix-plan'
  /** ?page=<n> is the 1-based page; absent is page 1. */
  page?: number
  /** ?size=<n> is one of findingsPageSizes; absent is 50. */
  size?: FindingsPageSize
  /** ?sort=<column> orders the list server-side; absent keeps the default. */
  sort?: FindingsSort
  /** ?order=desc reverses the sort; absent is ascending. */
  order?: SortOrder
  /** ?q= is a text search over title, rule, package and path; absent is none. */
  q?: string
}

/**
 * parseFindingsSearch reads ?view=single, ?asset=<id>, ?tab=fix-plan, ?page=<n>,
 * ?size=<n> and ?q=<text> from the Findings route. Without an asset the view
 * defaults to grouped (#106), so its URL is the bare path; an unknown view falls
 * back to that default. ?asset= forces single and drops any view. A page below 2
 * or a size that is not offered is dropped, so the URL stays canonical. ?q= is
 * trimmed and capped, and the fix plan tab, which is not a findings list, drops
 * it.
 */
export function parseFindingsSearch(
  search: Record<string, unknown>,
): FindingsSearch {
  const asset = parseAssetSearch(search)
  const page = parsePositiveInt(search.page)
  const size = parsePageSize(search.size)
  const sort = parseSortColumn(search.sort, findingsSortColumns)
  const order = sort === undefined ? undefined : parseSortOrder(search.order)
  const q = parseSearchQuery(search.q)
  const paging: Pick<FindingsSearch, 'page' | 'size' | 'sort' | 'order' | 'q'> = {
    ...(page !== undefined && page > 1 ? { page } : {}),
    ...(size !== undefined && size !== defaultFindingsPageSize ? { size } : {}),
    ...(sort === undefined ? {} : { sort }),
    ...(order === undefined ? {} : { order }),
    ...(q === undefined ? {} : { q }),
  }
  if (search.tab === 'fix-plan') {
    return { tab: 'fix-plan', ...asset }
  }
  if (asset.asset !== undefined) {
    return { ...asset, ...paging }
  }
  return search.view === 'single'
    ? { view: 'single', ...paging }
    : { ...paging }
}

/** MaxSearchQueryLength caps the findings search, like the API's q parameter. */
const maxSearchQueryLength = 200

/**
 * parseSearchQuery keeps a trimmed, non-empty search, cut to the length the API
 * accepts so a long shared link still lists findings instead of failing.
 */
function parseSearchQuery(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined
  const query = [...raw.trim()].slice(0, maxSearchQueryLength).join('')
  return query === '' ? undefined : query
}

/** parsePositiveInt reads a positive integer from a search value. */
function parsePositiveInt(raw: unknown): number | undefined {
  if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) {
    return raw
  }
  if (typeof raw === 'string' && /^[1-9]\d*$/.test(raw)) {
    return Number(raw)
  }
  return undefined
}

/** parsePageSize keeps only the sizes the page-size select offers. */
function parsePageSize(raw: unknown): FindingsPageSize | undefined {
  const value = parsePositiveInt(raw)
  return findingsPageSizes.find((size) => size === value)
}

/** ScanDiffSearch is the scan diff route's optional baseline scan (#17). */
export type ScanDiffSearch = {
  /** ?against=<id> compares with that scan instead of the previous one. */
  against?: number
}

/**
 * parseScanDiffSearch reads ?against=<id> from the diff route. A missing or
 * malformed id is dropped, so /scans/7/diff compares with the previous succeeded
 * scan rather than failing the route.
 */
export function parseScanDiffSearch(
  search: Record<string, unknown>,
): ScanDiffSearch {
  const raw = search.against
  if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) {
    return { against: raw }
  }
  if (typeof raw === 'string' && /^[1-9]\d*$/.test(raw)) {
    return { against: Number(raw) }
  }
  return {}
}

/** ProjectsTab names the two views of the Repositories section (#88). */
export type ProjectsTab = 'projects' | 'scans'

/** ProjectsSearch is the Repositories route's search params; the default tab is absent. */
export type ProjectsSearch = {
  tab?: 'scans'
  /** The Scans tab's project filter (#54); only kept on that tab. */
  asset?: number
  /** ?sort=<column> orders the scan list server-side; absent keeps the default. */
  sort?: ScanSort
  /** ?order=desc reverses the sort; absent is ascending. */
  order?: SortOrder
}

/**
 * parseProjectsTabSearch reads ?tab=scans from the Repositories route. Every
 * other value, including a missing one, is the Repositories tab, so
 * /repositories stays canonical and a mistyped tab never hides the list.
 * ?asset= filters the Scans tab and is dropped on the Repositories tab, which
 * has no filter.
 */
export function parseProjectsTabSearch(
  search: Record<string, unknown>,
): ProjectsSearch {
  if (search.tab !== 'scans') return {}
  const sort = parseSortColumn(search.sort, scanSortColumns)
  const order = sort === undefined ? undefined : parseSortOrder(search.order)
  return {
    tab: 'scans',
    ...parseAssetSearch(search),
    ...(sort === undefined ? {} : { sort }),
    ...(order === undefined ? {} : { order }),
  }
}

/**
 * ContainersTab names one tab of the Containers page (#120): the local Docker
 * daemon, one AWS connection by id, or the images whose connection is gone.
 */
export type ContainersTab = 'docker' | 'orphaned' | `aws-${number}`

/** ContainersSearch is the Containers route's search params. */
export type ContainersSearch = {
  /** ?tab=docker, ?tab=aws-<id> or ?tab=orphaned; absent is the first tab. */
  tab?: ContainersTab
}

/**
 * parseContainersTab reads ?tab=<source> from the Containers route. Only the
 * known shapes survive; which tab exists depends on the daemon and the AWS
 * connections, so a well-formed but stale value (a removed connection) is kept
 * here and the page falls back to its first tab.
 */
export function parseContainersTab(
  search: Record<string, unknown>,
): ContainersSearch {
  const raw = search.tab
  if (raw === 'docker' || raw === 'orphaned') return { tab: raw }
  if (typeof raw === 'string' && /^aws-\d+$/.test(raw)) {
    return { tab: raw as ContainersTab }
  }
  return {}
}

/** ConnectionsTab names the two kinds of source (#107). */
export type ConnectionsTab = 'repository' | 'registry'

/** ConnectionsSearch is the Connections route's search params. */
export type ConnectionsSearch = {
  /** ?tab=registry shows the registry placeholders; absent is Repository. */
  tab?: 'registry'
}

/**
 * parseConnectionsTab reads ?tab=registry from the Connections route. The
 * Repository tab is the default, so its URL stays the bare path and an unknown
 * tab falls back to it rather than hiding the GitHub setup.
 */
export function parseConnectionsTab(
  search: Record<string, unknown>,
): ConnectionsSearch {
  return search.tab === 'registry' ? { tab: 'registry' } : {}
}

/** ConfigurationsTab names the Configuration page's sections. */
export type ConfigurationsTab =
  | 'modules'
  | 'policies'
  | 'notifications'
  | 'ai'
  | 'mcp'
  | 'appearance'
  | 'about'

/** ConfigurationsSearch is the Configuration route's search params. */
export type ConfigurationsSearch = {
  /** ?tab=<section>; absent is Modules. */
  tab?: Exclude<ConfigurationsTab, 'modules'>
}

/**
 * parseConfigurationsTab reads ?tab=<section> from the Configuration route.
 * Modules is the default, so its URL stays the bare path, and an unknown tab
 * falls back to it rather than showing an empty panel.
 */
export function parseConfigurationsTab(
  search: Record<string, unknown>,
): ConfigurationsSearch {
  const raw = search.tab
  if (
    raw === 'policies' ||
    raw === 'notifications' ||
    raw === 'ai' ||
    raw === 'mcp' ||
    raw === 'appearance' ||
    raw === 'about'
  ) {
    return { tab: raw }
  }
  return {}
}
