import type { Scan } from '../api/scans'

/** DiffGroup names the three groups a scan diff reports (#17). */
export type DiffGroup = 'new' | 'fixed' | 'persisting'

/**
 * parseScanIdParam reads the diff route's $scanId. A path that is not a
 * positive integer names no scan, so the page can say so instead of asking the
 * API for /api/scans/NaN.
 */
export function parseScanIdParam(value: string): number | undefined {
  if (!/^[1-9]\d*$/.test(value)) return undefined
  return Number(value)
}

/**
 * scanDiffSubtitle is the line under the heading: what the scan on screen is
 * compared with, or that there is nothing to compare it with yet.
 */
export function scanDiffSubtitle(againstId: number | undefined): string {
  return againstId === undefined
    ? 'first scan — nothing to compare, every finding is new'
    : `compared with scan #${String(againstId)}`
}

/**
 * compareBaselines lists what the page can compare with: the asset's other
 * succeeded scans, in the order the API returned them (newest first). Queued,
 * running and failed scans have no complete finding set.
 */
export function compareBaselines(
  scans: readonly Scan[],
  scanId: number,
): Scan[] {
  return scans.filter(
    (scan) => scan.id !== scanId && scan.status === 'succeeded',
  )
}

/** diffGroupEmptyText is the muted line a group shows when it has no findings. */
export function diffGroupEmptyText(group: DiffGroup): string {
  switch (group) {
    case 'new':
      return 'No findings are new in this scan.'
    case 'fixed':
      return 'No findings were fixed since the scan it is compared with.'
    case 'persisting':
      return 'No findings persisted from the scan it is compared with.'
  }
}
