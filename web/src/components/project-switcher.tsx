import { useNavigate, useRouterState } from '@tanstack/react-router'

import type { Asset } from '../api/assets'
import { useT } from '../lib/i18n'
import type { FindingsSearch } from '../lib/urls'
import { pageHeadingId } from './page-band'

/**
 * ProjectSwitcher is the Findings band's title: picking a project opens its
 * page and "All assets" returns to the fleet-wide list. It keeps the tab and
 * the list state that make sense on either page, and stays a native select so
 * its accessible name and keyboard behaviour are the platform's.
 */
export function ProjectSwitcher({
  assets,
  current,
  heading = 'h1',
  onChange,
}: {
  assets: readonly Asset[]
  current: Asset | undefined
  /** The page's h1 by default; a page with its own title shows a compact span. */
  heading?: 'h1' | 'none'
  /** Where a pick goes; the default is the Findings list and its project pages. */
  onChange?: (assetId: number | null) => void
}) {
  const t = useT()
  const navigate = useNavigate()
  const search = useRouterState({
    select: (state) => state.location.search,
  }) as FindingsSearch
  const kept = {
    ...(search.tab === undefined ? {} : { tab: search.tab }),
    ...(search.q === undefined ? {} : { q: search.q }),
    ...(search.size === undefined ? {} : { size: search.size }),
    ...(search.sort === undefined ? {} : { sort: search.sort }),
    ...(search.order === undefined ? {} : { order: search.order }),
  }
  const repos = assets.filter((asset) => asset.kind !== 'image')
  const images = assets.filter((asset) => asset.kind === 'image')
  const title = current?.display_name ?? t('findings.filter.allProjects')

  return (
    // The visible title is the h1; the native select is a sibling overlaid on
    // it, so the heading names the page and the control stays a real select.
    <span className="relative inline-flex max-w-full items-center gap-1.5 rounded-md px-1 hover:bg-hover focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-muted">
      {heading === 'h1' ? (
        <h1
          id={pageHeadingId}
          tabIndex={-1}
          title={title}
          className="min-w-0 max-w-[min(36rem,72vw)] truncate text-2xl font-semibold tracking-tight text-fg focus:outline-none"
        >
          {title}
        </h1>
      ) : (
        <span
          title={title}
          className="min-w-0 max-w-[min(20rem,60vw)] truncate text-sm font-medium text-fg"
        >
          {title}
        </span>
      )}
      <span
        aria-hidden="true"
        className="shrink-0 text-lg leading-none text-muted"
      >
        ⌄
      </span>
      {/* The select covers the label, so the title is sized by its text (not by
          the longest option) and stays a real select for the platform's menu
          and keyboard behaviour. */}
      <select
        id="findings-project"
        aria-label={t('findings.filter.project')}
        value={current === undefined ? '' : String(current.id)}
        onChange={(event) => {
          const value = event.target.value
          const assetId = value === '' ? null : Number(value)
          if (onChange !== undefined) {
            onChange(assetId)
            return
          }
          void (assetId === null
            ? navigate({ to: '/findings', search: { ...kept, tab: undefined } })
            : navigate({
                to: '/findings/$assetId',
                params: { assetId: String(assetId) },
                search: kept,
              }))
        }}
        // ponytail: the native menu takes the select's font size; text-sm keeps
        // it normal-sized under the large title. Custom popover if styling matters.
        className="absolute inset-0 h-full w-full cursor-pointer text-sm opacity-0"
      >
        <option value="">{t('findings.filter.allProjects')}</option>
        {repos.length > 0 ? (
          <optgroup label={t('findings.filter.group.repositories')}>
            {repos.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.display_name}
              </option>
            ))}
          </optgroup>
        ) : null}
        {images.length > 0 ? (
          <optgroup label={t('findings.filter.group.images')}>
            {images.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.display_name}
              </option>
            ))}
          </optgroup>
        ) : null}
      </select>
    </span>
  )
}
