import type { Asset } from '../api/assets'
import type { SeverityTotals } from '../api/reports'

/** AssetStats is the summary a page hero shows for the assets it loaded. */
export type AssetStats = {
  /** Assets scanned daily or weekly (an "off" schedule does not count). */
  scheduled: number
  /** Open findings across the assets, per severity. */
  open: SeverityTotals
  /** The newest finished scan's time, or undefined when none has finished. */
  lastScan: string | undefined
}

/**
 * assetStats derives the page hero's figures from the asset list the page
 * already has, so neither page needs a summary endpoint of its own.
 */
export function assetStats(assets: readonly Asset[]): AssetStats {
  const open: SeverityTotals = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  }
  let scheduled = 0
  let lastScan: string | undefined

  for (const asset of assets) {
    open.critical += asset.open_counts.critical
    open.high += asset.open_counts.high
    open.medium += asset.open_counts.medium
    open.low += asset.open_counts.low
    open.unknown += asset.open_counts.unknown
    if (asset.scan_schedule === 'daily' || asset.scan_schedule === 'weekly') {
      scheduled += 1
    }
    // ISO timestamps sort as strings.
    const finished = asset.last_scan?.finished_at
    if (finished !== undefined && (lastScan === undefined || finished > lastScan)) {
      lastScan = finished
    }
  }

  return { scheduled, open, lastScan }
}
