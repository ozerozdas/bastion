import { Fragment, type ReactNode } from 'react'

import { cn } from '../lib/utils'

export type FilterOption = {
  value: string
  label: string
  /** Consecutive options with the same group share one <optgroup>. */
  group?: string
}

export type FilterField = {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  /** select (the default) or a free-text search box. */
  kind?: 'select' | 'search'
  /** Placeholder of a search box. */
  placeholder?: string
  options: readonly FilterOption[]
  /** Extra classes for the field wrapper, usually a width. */
  className?: string
}

export type FilterBarProps = {
  fields: readonly FilterField[]
  /** Accessible name for the bar, e.g. "Report filters". */
  label?: string
  /** Stacked puts the label above the control; inline puts it before it. */
  layout?: 'stacked' | 'inline'
  /** bordered draws the card surface the reports page uses. */
  bordered?: boolean
  /**
   * Fields flow in one column on phones, two between sm and lg, and the usual
   * wrapping row from lg up. Children then take a row of their own below lg.
   */
  fieldGrid?: boolean
  /** hideLabels keeps stacked labels for screen readers only; the controls speak for themselves. */
  hideLabels?: boolean
  /** Content after the fields, e.g. a note about the view on screen. */
  children?: ReactNode
  /** Content under the row inside the card, e.g. an inline disclosure panel. */
  panel?: ReactNode
  /** Content under the panel inside the card, e.g. removable filter chips. */
  activeFilters?: ReactNode
}

const stackedInput =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'
const inlineSelect =
  'h-8 max-w-full min-w-0 rounded-md border border-border-strong bg-surface px-2 text-[0.8125rem] text-fg'

/** optionNodes renders options, folding consecutive same-group ones into an optgroup. */
function optionNodes(options: readonly FilterOption[]): ReactNode[] {
  const nodes: ReactNode[] = []
  let start = 0
  while (start < options.length) {
    const group = options[start].group
    let end = start + 1
    while (end < options.length && options[end].group === group) end += 1
    const items = options.slice(start, end).map((option) => (
      <option key={option.value} value={option.value}>
        {option.label}
      </option>
    ))
    nodes.push(
      group === undefined ? (
        items
      ) : (
        <optgroup key={group} label={group}>
          {items}
        </optgroup>
      ),
    )
    start = end
  }
  return nodes
}

/**
 * FilterBar is the shared filter row. Callers pass only the fields they need,
 * so a page can show one select or four without a variant per page.
 */
export function FilterBar({
  fields,
  label,
  layout = 'stacked',
  bordered = true,
  fieldGrid = false,
  hideLabels = false,
  children,
  panel,
  activeFilters,
}: FilterBarProps) {
  const stacked = layout === 'stacked'
  // Findings has always wrapped its filters in a section; the Scans tab's inline
  // row is a plain div on the page.
  const Wrapper = stacked ? 'section' : 'div'
  const card = bordered && 'rounded-card border border-border-subtle bg-surface p-4'
  const row = cn(
    stacked ? 'items-end gap-3' : 'items-center gap-2',
    fieldGrid && stacked
      ? 'grid grid-cols-1 sm:grid-cols-2 lg:flex lg:flex-wrap'
      : 'flex flex-wrap',
  )

  const fieldNodes = fields.map((field) => {
    const control =
      field.kind === 'search' ? (
        <input
          id={field.id}
          type="search"
          value={field.value}
          onChange={(event) => field.onChange(event.target.value)}
          placeholder={field.placeholder}
          autoComplete="off"
          spellCheck={false}
          // The API refuses a q above 200 characters; keep the box inside it.
          maxLength={200}
          className={stacked ? stackedInput : inlineSelect}
        />
      ) : (
        <select
          id={field.id}
          value={field.value}
          onChange={(event) => field.onChange(event.target.value)}
          className={stacked ? stackedInput : inlineSelect}
        >
          {optionNodes(field.options)}
        </select>
      )

    if (!stacked) {
      return (
        <Fragment key={field.id}>
          <label htmlFor={field.id} className="text-xs text-muted">
            {field.label}
          </label>
          {control}
        </Fragment>
      )
    }

    return (
      <div key={field.id} className={cn('flex flex-col gap-1', field.className)}>
        <label
          htmlFor={field.id}
          className={cn('text-xs font-medium text-muted', hideLabels && 'sr-only')}
        >
          {field.label}
        </label>
        {control}
      </div>
    )
  })

  // A page with a panel or chips keeps them inside the card, so the row becomes
  // one line of a column instead of the wrapper itself.
  if (panel === undefined && activeFilters === undefined) {
    return (
      <Wrapper aria-label={label} className={cn(row, card)}>
        {fieldNodes}
        {children}
      </Wrapper>
    )
  }

  return (
    <Wrapper aria-label={label} className={cn('flex flex-col gap-3', card)}>
      <div className={row}>
        {fieldNodes}
        {children}
      </div>
      {panel}
      {activeFilters}
    </Wrapper>
  )
}
