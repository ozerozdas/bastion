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
