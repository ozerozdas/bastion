import { Fragment, type ReactNode } from 'react'

import { cn } from '../lib/utils'

export type FilterOption = {
  value: string
  label: string
}

export type FilterField = {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
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
  /** Content after the fields, e.g. a note about the view on screen. */
  children?: ReactNode
}

const stackedInput =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'
const inlineSelect =
  'h-8 rounded-md border border-border-strong bg-surface px-2 text-[13px] text-fg'

/**
 * FilterBar is the shared filter row. Callers pass only the fields they need,
 * so a page can show one select or four without a variant per page.
 */
export function FilterBar({
  fields,
  label,
  layout = 'stacked',
  bordered = true,
  children,
}: FilterBarProps) {
  const stacked = layout === 'stacked'

  return (
    <section
      aria-label={label}
      className={cn(
        'flex flex-wrap',
        stacked ? 'items-end gap-3' : 'items-center gap-2',
        bordered && 'rounded-card border border-border-subtle bg-surface p-4',
      )}
    >
      {fields.map((field) => {
        const options = field.options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))

        if (!stacked) {
          return (
            <Fragment key={field.id}>
              <label htmlFor={field.id} className="text-xs text-muted">
                {field.label}
              </label>
              <select
                id={field.id}
                value={field.value}
                onChange={(event) => field.onChange(event.target.value)}
                className={inlineSelect}
              >
                {options}
              </select>
            </Fragment>
          )
        }

        return (
          <div key={field.id} className={cn('flex flex-col gap-1', field.className)}>
            <label htmlFor={field.id} className="text-xs font-medium text-muted">
              {field.label}
            </label>
            <select
              id={field.id}
              value={field.value}
              onChange={(event) => field.onChange(event.target.value)}
              className={stackedInput}
            >
              {options}
            </select>
          </div>
        )
      })}
      {children}
    </section>
  )
}
