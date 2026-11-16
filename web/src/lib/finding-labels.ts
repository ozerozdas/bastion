import type { FindingState, FindingType, Severity } from '../api/findings'
import type { SeverityTotals } from '../api/reports'
import { t } from './i18n'

/** typeLabels holds the translation key of each finding kind (§8). */
export const typeLabels: Record<FindingType, string> = {
  vulnerability: 'type.vulnerability',
  secret: 'type.secret',
  outdated: 'type.outdated',
  misconfig: 'type.misconfig',
  license: 'type.license',
  malware: 'type.malware',
  sast: 'type.sast',
}

export const stateLabels: Record<FindingState, string> = {
  ignored: 'state.ignored',
  accepted_risk: 'state.accepted_risk',
  false_positive: 'state.false_positive',
}

/** severityLabel is the severity's name for a badge: Critical … Unknown. */
export function severityLabel(severity: Severity): string {
  return t(`severity.${severity}`)
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
    .map((severity) =>
      t('severity.summary.item', {
        count: counts[severity],
        severity: t(`severity.lower.${severity}`),
      }),
    )
  return parts.length === 0 ? t('severity.summary.none') : parts.join(', ')
}
