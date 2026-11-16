import { useEffect, useState, type FormEvent } from 'react'

import { formatNumber, useT } from '../lib/i18n'
import { findingsPageSizes, type FindingsPageSize } from '../lib/urls'
import { Button } from './ui/button'

const inputClass =
  'h-7 rounded-md border border-border-strong bg-surface px-2 text-xs text-fg tabular-nums'

export type PagerProps = {
  /** Every row the filters match, not just this page. */
  total: number
  /** 1-based page. */
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  onPageSizeChange: (size: FindingsPageSize) => void
}

/**
 * Pager is the table footer: the visible range, prev/next, a page jump and the
 * page size. The page and size live in the route's search params, so the caller
 * owns the state and this component only reports the choice.
 */
export function Pager({
  total,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: PagerProps) {
  const t = useT()
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1
  const last = Math.min(page * pageSize, total)
  const [jump, setJump] = useState(String(page))

  // A page change from outside (a filter reset, a live refresh) wins over a
  // half-typed jump value.
  useEffect(() => {
    setJump(String(page))
  }, [page])

  function go(next: number) {
    const clamped = Math.min(Math.max(1, next), pageCount)
    if (clamped !== page) onPageChange(clamped)
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    go(Number(jump))
  }

  return (
    <nav
      aria-label={t('pager.aria')}
      className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border-subtle pt-3 text-xs text-muted"
    >
      <span className="tabular-nums">
        {t('pager.range', {
          first: formatNumber(first),
          last: formatNumber(last),
          total: formatNumber(total),
        })}
      </span>
      <div className="ml-auto flex items-center gap-1.5">
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={page <= 1}
          onClick={() => go(page - 1)}
        >
          {t('pager.previous')}
        </Button>
        <form onSubmit={submit} className="flex items-center gap-1.5">
          <label htmlFor="pager-page" className="sr-only">
            {t('pager.page')}
          </label>
          <input
            id="pager-page"
            type="number"
            min={1}
            max={pageCount}
            value={jump}
            onChange={(event) => setJump(event.target.value)}
            className={`${inputClass} w-14 text-center`}
          />
          <span className="tabular-nums">
            {t('pager.of', { count: formatNumber(pageCount) })}
          </span>
        </form>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={page >= pageCount}
          onClick={() => go(page + 1)}
        >
          {t('pager.next')}
        </Button>
      </div>
      <label className="flex items-center gap-1.5">
        <span>{t('pager.rowsPerPage')}</span>
        <select
          value={pageSize}
          onChange={(event) =>
            onPageSizeChange(Number(event.target.value) as FindingsPageSize)
          }
          className={inputClass}
        >
          {findingsPageSizes.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </label>
    </nav>
  )
}
