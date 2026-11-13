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

/** FindingsSearch is the Findings route's search params; the default view is absent. */
export type FindingsSearch = {
  /** ?view=grouped shows one row per rule + type across projects. */
  view?: 'grouped'
  /** Narrows the list to one project; absent means every project. */
  asset?: number
}

/**
 * parseFindingsSearch reads ?view=grouped and ?asset=<id> from the Findings
 * route. Single is the default, so its URL stays the bare path, and an unknown
 * view falls back to it rather than hiding rows. ?asset= keeps the validation
 * the old reports route had.
 */
export function parseFindingsSearch(
  search: Record<string, unknown>,
): FindingsSearch {
  return {
    ...(search.view === 'grouped' ? { view: 'grouped' as const } : {}),
    ...parseAssetSearch(search),
  }
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
