import type { SeverityTotals } from '../api/reports'
import { severitySummary } from '../lib/finding-labels'
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
      aria-label={`${String(count)} open ${label} findings`}
    >
      {count}
    </Badge>
  )
}

/**
 * SeverityCountBadges shows counts the way the Projects table does, with the
 * same badges, and adds the counts as one screen-reader sentence so the row
 * reads as text and not as four colours.
 */
export function SeverityCountBadges({ counts }: { counts: SeverityTotals }) {
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
