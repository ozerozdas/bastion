import type { CIRun, SeverityTotals } from '../api/reports'

/** ciFailOnLevels are the failure policies the CI history offers, in order. */
export const ciFailOnLevels = [
  'none',
  'critical',
  'high',
  'medium',
] as const

/** CIFailOn is one fail-on policy: status only, or a severity floor. */
export type CIFailOn = (typeof ciFailOnLevels)[number]

/** FailOnSeverity is the severity floor, without the status-only option. */
export type FailOnSeverity = Exclude<CIFailOn, 'none'>

/**
 * severityCountAtOrAbove sums the recorded findings at or above a severity, so
 * "high" counts critical and high together.
 */
export function severityCountAtOrAbove(
  counts: SeverityTotals,
  level: FailOnSeverity,
): number {
  switch (level) {
    case 'critical':
      return counts.critical
    case 'high':
      return counts.critical + counts.high
    case 'medium':
      return counts.critical + counts.high + counts.medium
  }
}

/**
 * runFails classifies one CI run under a fail-on policy: anything that did not
 * succeed failed, and a severity floor fails the run when the scan recorded a
 * finding at or above it.
 */
export function runFails(
  run: Pick<CIRun, 'status' | 'counts'>,
  failOn: CIFailOn,
): boolean {
  if (run.status !== 'succeeded') return true
  return failOn !== 'none' && severityCountAtOrAbove(run.counts, failOn) > 0
}
