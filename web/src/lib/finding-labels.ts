import type { FindingState, FindingType, Severity } from '../api/findings'
import type { SeverityTotals } from '../api/reports'

/** typeLabels names each finding kind; license findings are informational (§8). */
export const typeLabels: Record<FindingType, string> = {
  vulnerability: 'Vulnerability',
  secret: 'Secret',
  outdated: 'Outdated package',
  misconfig: 'Misconfiguration',
  license: 'License',
  malware: 'Malware',
  sast: 'Code issue',
}

export const stateLabels: Record<FindingState, string> = {
  ignored: 'Ignored',
  accepted_risk: 'Accepted risk',
  false_positive: 'False positive',
}

/** severityTone keeps severity colour on the badge only (§7). */
export const severityTone: Record<
  Severity,
  'critical' | 'high' | 'medium' | 'low' | 'neutral'
> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'neutral',
}

export function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

/** severityOrder is the reading order of the counts, worst first (§7). */
const severityOrder: (keyof SeverityTotals)[] = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
]

/**
 * severitySummary spells counts out as text, so a row of severity colours is
 * still readable: "2 critical, 1 high", or "no findings" when nothing was
 * recorded. Zero severities are left out; the badges carry them visually.
 */
export function severitySummary(counts: SeverityTotals): string {
  const parts = severityOrder
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${String(counts[severity])} ${severity}`)
  return parts.length === 0 ? 'no findings' : parts.join(', ')
}
