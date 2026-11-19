import type { SeverityTotals } from '../api/reports'
import { severitySummary } from '../lib/finding-labels'
import { t, useT } from '../lib/i18n'
import { Badge } from './ui/badge'

/** severityCounts is the fixed order and tone of the four severity counts. */
export const severityCounts: {
  key: 'critical' | 'high' | 'medium' | 'low'
  tone: 'critical' | 'high' | 'medium' | 'low'
}[] = [
  { key: 'critical', tone: 'critical' },
  { key: 'high', tone: 'high' },
  { key: 'medium', tone: 'medium' },
  { key: 'low', tone: 'low' },
]

/** CountBadge keeps severity colour on the badge and greys out zero counts. */
export function CountBadge({
  count,
  tone,
  label,
}: {
  count: number
  tone: 'critical' | 'high' | 'medium' | 'low'
  label: string
}) {
  return (
    <Badge
      tone={tone}
      className={count === 0 ? 'tabular-nums opacity-40' : 'tabular-nums'}
      aria-label={t('severity.openCount', {
        count,
        severity: t(`severity.lower.${label}`),
      })}
    >
      {count}
    </Badge>
  )
}

/**
 * OpenSeverityCounts is the single-line style the Repositories table uses: one
 * badge per non-zero severity, or a muted dash when nothing is open.
 */
export function OpenSeverityCounts({ counts }: { counts: SeverityTotals }) {
  useT()
  const shown = severityCounts.filter((severity) => counts[severity.key] > 0)
  if (shown.length === 0) {
    return (
      <span className="text-[0.8125rem] text-faint">
        <span aria-hidden="true">—</span>
        <span className="sr-only">{t('repos.findings.none')}</span>
      </span>
    )
  }
  return (
    <span className="flex flex-nowrap items-center gap-1">
      {shown.map((severity) => (
        <CountBadge
          key={severity.key}
          count={counts[severity.key]}
          tone={severity.tone}
          label={severity.key}
        />
      ))}
    </span>
  )
}

/**
 * SeverityCountBadges shows counts the way the Projects table does, with the
 * same badges, and adds the counts as one screen-reader sentence so the row
 * reads as text and not as four colours.
 */
export function SeverityCountBadges({ counts }: { counts: SeverityTotals }) {
  useT()
  return (
    <>
      <span aria-hidden="true" className="flex flex-wrap gap-1">
        {severityCounts.map((severity) => (
          <CountBadge
            key={severity.key}
            count={counts[severity.key]}
            tone={severity.tone}
            label={severity.key}
          />
        ))}
      </span>
      <span className="sr-only">{severitySummary(counts)}</span>
    </>
  )
}
