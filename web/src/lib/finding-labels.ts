import type { FindingState, FindingType, Severity } from '../api/findings'

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
