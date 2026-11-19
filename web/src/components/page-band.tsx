import { Fragment, useEffect, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

import { openFindingTotal, type SeverityTotals } from '../api/reports'
import { severitySummary } from '../lib/finding-labels'

/** pageBandId is the AppShell slot the band is portalled into. */
export const pageBandId = 'page-band'
/** A banded page's own title, so navigation focus still lands on it. */
export const pageHeadingId = 'page-heading'

/**
 * PageBand portals a full-bleed header band into the main area, above the
 * page-content column, so the band can span the window while its inner content
 * still follows the content-width preference.
 */
export function PageBand({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<HTMLElement | null>(null)
  useEffect(() => {
    setTarget(document.getElementById(pageBandId))
  }, [])
  return target ? createPortal(children, target) : null
}

/**
 * BandFrame is the band's surface and its content column: the same width cap
 * and horizontal padding as `.page-content`, with a single bottom border.
 */
export function BandFrame({ children }: { children: ReactNode }) {
  return (
    <div className="border-b border-border-subtle bg-surface">
      <div className="page-band-inner mx-auto w-full px-4 sm:px-7">
        {children}
      </div>
    </div>
  )
}

const titleClass =
  'min-w-0 max-w-full truncate text-2xl font-semibold tracking-tight focus:outline-none'

/**
 * BandSummary is the title row of a band: the page title, small inline meta
 * items beside it, a subtitle under it and the primary actions on the right.
 * `heading` lets a page whose title already lives in the app header (a project
 * page under Findings) use an h2 instead of the page's h1.
 */
export function BandSummary({
  title,
  meta,
  subtitle,
  actions,
  below,
  heading = 'h1',
}: {
  title: ReactNode
  /** Compact chips/items beside the title, e.g. counts or a status badge. */
  meta?: ReactNode
  subtitle?: ReactNode
  /** The page's primary actions, kept at the right end of the title row. */
  actions?: ReactNode
  /** A full-width row under the title, e.g. an expanded editor or an error. */
  below?: ReactNode
  heading?: 'h1' | 'h2'
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            {heading === 'h1' ? (
              <h1 id={pageHeadingId} tabIndex={-1} className={titleClass}>
                {title}
              </h1>
            ) : (
              <h2 className={titleClass}>{title}</h2>
            )}
            {meta === undefined ? null : meta}
          </div>
          {subtitle === undefined ? null : (
            <p className="min-w-0 truncate text-xs text-muted">{subtitle}</p>
          )}
        </div>
        {actions === undefined ? null : (
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        )}
      </div>
      {below}
    </div>
  )
}

/** BandMetaItem is one labelled figure in a band's inline meta row. */
export type BandMetaItem = {
  /** Stable key for the React list; not shown. */
  key: string
  /** The small, faint name before the figure. */
  label: string
  value: ReactNode
}

/** BandMeta renders compact inline items, separated by a middle dot. */
export function BandMeta({ items }: { items: readonly BandMetaItem[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
      {items.map((item, index) => (
        <Fragment key={item.key}>
          {index > 0 ? (
            <span aria-hidden="true" className="text-faint">
              ·
            </span>
          ) : null}
          <span className="flex items-center gap-1.5 whitespace-nowrap">
            <span className="text-faint">{item.label}</span>
            <span className="flex items-center gap-1.5 font-semibold text-fg tabular-nums">
              {item.value}
            </span>
          </span>
        </Fragment>
      ))}
    </div>
  )
}

/** BandHeader is a band without tabs, for a page whose panel has no views. */
export function BandHeader({ children }: { children: ReactNode }) {
  return (
    <PageBand>
      <BandFrame>
        <div className="pt-4 pb-3">{children}</div>
      </BandFrame>
    </PageBand>
  )
}

const severityRows = [
  { key: 'critical', mark: 'bg-critical' },
  { key: 'high', mark: 'bg-high' },
  { key: 'medium', mark: 'bg-medium' },
  { key: 'low', mark: 'bg-low' },
  { key: 'unknown', mark: 'bg-border-strong' },
] as const

/**
 * SeverityMix is the open findings broken down the way the dashboard hero does
 * it: one coloured dot per non-zero severity, with its count. It says nothing
 * when there are no findings, so the total beside it can stand alone.
 */
export function SeverityMix({ totals }: { totals: SeverityTotals }) {
  if (openFindingTotal(totals) === 0) return null
  return (
    <>
      <span
        aria-hidden="true"
        className="flex items-center gap-2 text-[0.75rem] font-normal text-muted"
      >
        {severityRows
          .filter((row) => totals[row.key] > 0)
          .map((row) => (
            <span key={row.key} className="flex items-center gap-1">
              <span className={`size-1.5 rounded-full ${row.mark}`} />
              <span className="tabular-nums">{totals[row.key]}</span>
            </span>
          ))}
      </span>
      <span className="sr-only">{severitySummary(totals)}</span>
    </>
  )
}
