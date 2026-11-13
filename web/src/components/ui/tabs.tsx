import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react'

import { cn } from '../../lib/utils'

/** TabItem is one tab's value and its visible label. */
export type TabItem<T extends string> = {
  value: T
  label: string
}

/**
 * Tabs is the WAI-ARIA tabs pattern with automatic activation (issue #88):
 * only the selected tab is in the tab order, Left/Right wrap around it,
 * Home/End jump to the ends, and focus moves with the selection. The tablist
 * is a named group in the page, so the panel content follows it in reading
 * order.
 */
export function Tabs<T extends string>({
  label,
  items,
  value,
  onChange,
  children,
}: {
  /** Accessible name of the tablist, e.g. "Projects views". */
  label: string
  items: readonly TabItem<T>[]
  /** The selected tab; the caller owns it, usually through the URL. */
  value: T
  onChange: (value: T) => void
  /** Content of the selected panel. */
  children: ReactNode
}) {
  const id = useId()
  const buttons = useRef(new Map<T, HTMLButtonElement>())
  const selected = items.find((item) => item.value === value) ?? items[0]

  function tabId(tab: T): string {
    return `${id}-${tab}-tab`
  }

  function panelId(tab: T): string {
    return `${id}-${tab}-panel`
  }

  function moveFocus(event: KeyboardEvent<HTMLElement>, index: number) {
    let next: number
    switch (event.key) {
      case 'ArrowRight':
        next = (index + 1) % items.length
        break
      case 'ArrowLeft':
        next = (index - 1 + items.length) % items.length
        break
      case 'Home':
        next = 0
        break
      case 'End':
        next = items.length - 1
        break
      default:
        return
    }
    event.preventDefault()
    const target = items[next]
    onChange(target.value)
    buttons.current.get(target.value)?.focus()
  }

  return (
    <div className="flex flex-col gap-4">
      <div
        role="tablist"
        aria-label={label}
        className="flex items-center gap-1 border-b border-border-subtle"
      >
        {items.map((item, index) => {
          const active = item.value === selected.value
          return (
            <button
              key={item.value}
              ref={(node) => {
                if (node) {
                  buttons.current.set(item.value, node)
                } else {
                  buttons.current.delete(item.value)
                }
              }}
              type="button"
              role="tab"
              id={tabId(item.value)}
              aria-selected={active}
              // Only the selected panel is rendered; an IDREF must resolve.
              aria-controls={active ? panelId(item.value) : undefined}
              tabIndex={active ? 0 : -1}
              onClick={() => onChange(item.value)}
              onKeyDown={(event) => moveFocus(event, index)}
              className={cn(
                '-mb-px border-b-2 px-2.5 py-2 text-[13px] transition-colors',
                active
                  ? 'border-accent text-fg'
                  : 'border-transparent text-muted hover:text-fg',
              )}
            >
              {item.label}
            </button>
          )
        })}
      </div>

      <div
        role="tabpanel"
        id={panelId(selected.value)}
        aria-labelledby={tabId(selected.value)}
        tabIndex={0}
        className="flex flex-col gap-4 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
      >
        {children}
      </div>
    </div>
  )
}
