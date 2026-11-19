import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import type { Finding } from '../../api/findings'
import { owaspTop10Query, type OWASPCategory } from '../../api/reports'
import { EmptyState } from '../../components/empty-state'
import { FindingDrawer } from '../../components/finding-drawer'
import { formatNumber, useT } from '../../lib/i18n'
import { cn } from '../../lib/utils'
import {
  ReportCaption,
  ReportChevron,
  ReportError,
  ReportFindings,
  ReportLoading,
  ReportPanelHeading,
  reportCardClass,
  type ReportPanelProps,
} from './shared'

/** findingsShown caps one expanded category, so a huge fleet stays responsive. */
const findingsShown = 50

/** categoryTitleKeys maps a 2021 category id to its translated name. */
const categoryTitleKeys: Record<string, string> = {
  A01: 'reports.owasp-top10.category.A01',
  A02: 'reports.owasp-top10.category.A02',
  A03: 'reports.owasp-top10.category.A03',
  A04: 'reports.owasp-top10.category.A04',
  A05: 'reports.owasp-top10.category.A05',
  A06: 'reports.owasp-top10.category.A06',
  A07: 'reports.owasp-top10.category.A07',
  A08: 'reports.owasp-top10.category.A08',
  A09: 'reports.owasp-top10.category.A09',
  A10: 'reports.owasp-top10.category.A10',
}

/**
 * categoryLabel translates one category by id. Unmapped findings and ids this
 * build does not know fall back to the report's own title key and the API's
 * title, so an unknown category still reads sensibly.
 */
function categoryLabel(
  t: (key: string) => string,
  category: OWASPCategory,
): string {
  if (category.id === 'unmapped') return t('reports.owasp-top10.unmapped.title')
  const key = categoryTitleKeys[category.id]
  return key === undefined ? category.title : t(key)
}

/**
 * OwaspTop10Report groups the latest open findings by their OWASP Top 10 2021
 * category (#190). A category expands in place, and the finding rows open the
 * same drawer the findings list uses.
 */
export function OwaspTop10Report({ search }: ReportPanelProps) {
  const t = useT()
  const report = useQuery(owaspTop10Query(search.asset))
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const [openFinding, setOpenFinding] = useState<Finding | null>(null)

  if (report.isPending) return <ReportLoading />
  if (report.isError) return <ReportError error={report.error} />

  const categories = report.data.categories
  const mapped = categories.filter((category) => category.id !== 'unmapped')
  const unmapped = categories.find((category) => category.id === 'unmapped')
  const total = categories.reduce((sum, category) => sum + category.count, 0)

  if (total === 0) {
    return (
      <EmptyState
        title={t('reports.owasp-top10.empty.title')}
        body={t('reports.owasp-top10.empty.body')}
      />
    )
  }

  const max = Math.max(1, ...categories.map((category) => category.count))

  function toggle(id: string) {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <>
      <section className={reportCardClass}>
        <div className="flex flex-col gap-1">
          <ReportPanelHeading
            title={t('reports.owasp-top10.categories.title')}
            aside={t('reports.owasp-top10.count', { count: total })}
          />
          <ReportCaption>{t('reports.owasp-top10.caption')}</ReportCaption>
        </div>
        <ul aria-label={t('reports.owasp-top10.categories.title')} className="flex flex-col">
          {mapped.map((category) => (
            <li key={category.id} className="border-b border-border-subtle last:border-b-0">
              <OwaspRow
                category={category}
                max={max}
                open={expanded.has(category.id)}
                onToggle={() => toggle(category.id)}
                onOpen={setOpenFinding}
              />
            </li>
          ))}
        </ul>
      </section>

      {unmapped !== undefined && unmapped.count > 0 ? (
        <section className={reportCardClass}>
          <div className="flex flex-col gap-1">
            <ReportPanelHeading
              title={t('reports.owasp-top10.unmapped.title')}
              aside={formatNumber(unmapped.count)}
            />
            <ReportCaption>{t('reports.owasp-top10.unmapped.note')}</ReportCaption>
          </div>
          <ReportFindings
            findings={unmapped.findings}
            onOpen={setOpenFinding}
            ariaLabel={t('reports.owasp-top10.unmapped.title')}
          />
        </section>
      ) : null}

      {openFinding === null ? null : (
        <FindingDrawer
          key={openFinding.fingerprint}
          finding={openFinding}
          onClose={() => setOpenFinding(null)}
        />
      )}
    </>
  )
}

/** OwaspRow is one category: its count bar and, expanded, its findings. */
function OwaspRow({
  category,
  max,
  open,
  onToggle,
  onOpen,
}: {
  category: OWASPCategory
  max: number
  open: boolean
  onToggle: () => void
  onOpen: (finding: Finding) => void
}) {
  const t = useT()
  const expandable = category.count > 0
  const width = `${String((category.count / max) * 100)}%`
  const shown = category.findings.slice(0, findingsShown)
  const title = categoryLabel(t, category)

  const body = (
    <>
      <span className="w-9 shrink-0 font-mono text-xs text-faint">
        {category.id}
      </span>
      <span className="flex min-w-0 flex-1 flex-col gap-1">
        <span className="flex items-baseline justify-between gap-3">
          <span className="min-w-0 truncate text-[0.875rem]">{title}</span>
          <span
            className={cn(
              'shrink-0 text-xs tabular-nums',
              category.count === 0 ? 'text-faint' : 'text-muted',
            )}
          >
            {formatNumber(category.count)}
          </span>
        </span>
        <span
          aria-hidden="true"
          className="block h-1 w-full overflow-hidden rounded-full bg-hover"
        >
          {category.count === 0 ? null : (
            <span
              className="block h-full rounded-full bg-accent/60"
              style={{ width }}
            />
          )}
        </span>
      </span>
      {expandable ? <ReportChevron open={open} /> : <span className="size-3 shrink-0" />}
    </>
  )

  return (
    <div className="flex flex-col">
      {expandable ? (
        <button
          type="button"
          aria-expanded={open}
          onClick={onToggle}
          className="flex w-full items-center gap-3 rounded px-1 py-2.5 text-left transition-colors hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
        >
          {body}
          <span className="sr-only">
            {open ? t('reports.owasp-top10.hide') : t('reports.owasp-top10.show')}
          </span>
        </button>
      ) : (
        <div className="flex w-full items-center gap-3 px-1 py-2.5">{body}</div>
      )}
      {open && expandable ? (
        <div className="mb-2 border-l border-border-subtle pl-3 sm:ml-11">
          <ReportFindings findings={shown} onOpen={onOpen} ariaLabel={title} />
          {category.count > shown.length ? (
            <p className="px-1 pt-1 text-xs text-muted">
              {t('reports.owasp-top10.truncated', {
                shown: shown.length,
                total: category.count,
              })}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
