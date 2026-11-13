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

/** FindingsView names the two ways the Findings page lists rows (#90). */
export type FindingsView = 'single' | 'grouped'

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
}

/**
 * parseFindingsSearch reads ?view=single and ?asset=<id> from the Findings
 * route. Without an asset the view defaults to grouped (#106), so its URL is
 * the bare path; an unknown view falls back to that default. ?asset= forces
 * single, keeps the validation the old reports route had, and drops any view.
 */
export function parseFindingsSearch(
  search: Record<string, unknown>,
): FindingsSearch {
  const asset = parseAssetSearch(search)
  if (asset.asset !== undefined) {
    return asset
  }
  return search.view === 'single' ? { view: 'single' } : {}
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

/** ProjectsTab names the two views of the Projects section (#88). */
export type ProjectsTab = 'projects' | 'scans'

/** ProjectsSearch is the Projects route's search params; the default tab is absent. */
export type ProjectsSearch = {
  tab?: 'scans'
  /** The Scans tab's project filter (#54); only kept on that tab. */
  asset?: number
}

/**
 * parseProjectsTabSearch reads ?tab=scans from the Projects route. Every other
 * value, including a missing one, is the Projects tab, so /projects stays
 * canonical and a mistyped tab never hides the project list. ?asset= filters
 * the Scans tab and is dropped on the Projects tab, which has no filter.
 */
export function parseProjectsTabSearch(
  search: Record<string, unknown>,
): ProjectsSearch {
  if (search.tab !== 'scans') return {}
  return { tab: 'scans', ...parseAssetSearch(search) }
}
