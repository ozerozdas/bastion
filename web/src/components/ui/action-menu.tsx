import { Link } from '@tanstack/react-router'
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
  type RefObject,
} from 'react'
import { createPortal } from 'react-dom'

import { cn } from '../../lib/utils'
import { anchoredPosition } from './anchored'

/** ActionMenuRadio is the one-of-many choice a menu can carry, e.g. a schedule. */
export type ActionMenuRadio = {
  /** Accessible name of the group. */
  label: string
  /** Visible heading above the choices. */
  title: ReactNode
  value: string
  options: readonly { value: string; label: string }[]
  onChange: (value: string) => void
  disabled?: boolean
  /** A small control beside the heading, e.g. an InfoTip. */
  hint?: ReactNode
}

/**
 * ActionMenuItem is one row of a menu. `to` makes it a router link and `href`
 * an off-app link, so both keep the browser's own link behaviour; `onSelect`
 * makes it a button.
 */
export type ActionMenuItem = {
  key: string
  label: ReactNode
  onSelect?: () => void
  to?: string
  search?: Record<string, unknown>
  href?: string
  destructive?: boolean
  disabled?: boolean
}

const itemClass =
  'flex w-full items-center gap-2 rounded-[5px] px-2 py-1.5 text-left text-[0.8125rem] whitespace-nowrap text-fg outline-none hover:bg-hover focus:bg-hover'

/**
 * ActionMenu is the row's "⋯" menu: a compact replacement for the buttons that
 * crowded the table. It is rendered in a portal so a table's overflow cannot
 * clip it, flips above the trigger near the bottom of the window, and follows
 * the WAI-ARIA menu pattern: arrow keys and Home/End move, Escape and an
 * outside click close, and focus returns to the trigger.
 */
export function ActionMenu({
  label,
  items,
  radio,
  trailingItems,
  triggerRef,
  className,
}: {
  /** Accessible name of the button and of the menu, e.g. "Actions for acme/api". */
  label: string
  items: readonly ActionMenuItem[]
  /**
   * One or more one-of-many choices, e.g. a schedule and a repository link.
   * Each group renders as its own section under the items.
   */
  radio?: ActionMenuRadio | readonly ActionMenuRadio[]
  /** Items that follow the radio groups, e.g. the destructive ones. */
  trailingItems?: readonly ActionMenuItem[]
  /** The trigger, for callers that move focus back to it. */
  triggerRef?: RefObject<HTMLButtonElement | null>
  /** Extra classes for the trigger button. */
  className?: string
}) {
  const radios: readonly ActionMenuRadio[] =
    radio === undefined ? [] : Array.isArray(radio) ? radio : [radio]
  const button = useRef<HTMLButtonElement>(null)
  const menu = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<{ top: number; left: number } | null>(
    null,
  )

  function focusTrigger() {
    button.current?.focus()
  }

  function close(restoreFocus: boolean) {
    setOpen(false)
    setPosition(null)
    if (restoreFocus) {
      focusTrigger()
    }
  }

  // Place once the menu has a measured size, then reveal it.
  useLayoutEffect(() => {
    if (!open) return
    const triggerEl = button.current
    const menuEl = menu.current
    if (triggerEl === null || menuEl === null) return
    setPosition(
      anchoredPosition(triggerEl.getBoundingClientRect(), {
        width: menuEl.offsetWidth,
        height: menuEl.offsetHeight,
      }, { align: 'end' }),
    )
  }, [open])

  // The first item takes focus, as a menu expects. It waits for the placed
  // render: a hidden menu cannot take focus.
  useEffect(() => {
    if (!open || position === null) return
    menu.current
      ?.querySelector<HTMLElement>(
        '[role^="menuitem"]:not([aria-disabled="true"]), [data-menu-control]',
      )
      ?.focus()
  }, [open, position])

  useEffect(() => {
    if (!open) return

    function closeHere() {
      setOpen(false)
      setPosition(null)
    }
    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node
      if (
        button.current?.contains(target) ||
        menu.current?.contains(target)
      ) {
        return
      }
      closeHere()
    }

    document.addEventListener('pointerdown', onPointerDown)
    window.addEventListener('scroll', closeHere, true)
    window.addEventListener('resize', closeHere)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      window.removeEventListener('scroll', closeHere, true)
      window.removeEventListener('resize', closeHere)
    }
  }, [open])

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      event.stopPropagation()
      close(true)
      return
    }

    const focusable = [
      ...(menu.current?.querySelectorAll<HTMLElement>(
        '[role^="menuitem"]:not([aria-disabled="true"]), [data-menu-control]',
      ) ?? []),
    ]
    const current = focusable.findIndex((item) => item === document.activeElement)

    let next: number | undefined
    switch (event.key) {
      case 'ArrowDown':
        next = current + 1 >= focusable.length ? 0 : current + 1
        break
      case 'ArrowUp':
        next = current <= 0 ? focusable.length - 1 : current - 1
        break
      case 'Home':
        next = 0
        break
      case 'End':
        next = focusable.length - 1
        break
      case ' ':
        // A link does not activate on Space the way a button does.
        if (document.activeElement instanceof HTMLAnchorElement) {
          event.preventDefault()
          document.activeElement.click()
        }
        return
      default:
        return
    }
    event.preventDefault()
    focusable[next]?.focus()
  }

  // Choosing a menu item closes the menu; a radio choice (menuitemradio) leaves
  // it open, so a second option can be picked without reopening the menu.
  function onMenuClick(event: MouseEvent<HTMLDivElement>) {
    const item = (event.target as HTMLElement).closest<HTMLElement>(
      '[role="menuitem"]',
    )
    if (item === null || item.getAttribute('aria-disabled') === 'true') return
    close(true)
  }

  // A menu row is a link, an off-app anchor or a button; long labels truncate
  // so the menu never grows past its width.
  function renderItem(item: ActionMenuItem) {
    const content = <span className="min-w-0 flex-1 truncate">{item.label}</span>
    if (item.to !== undefined) {
      return (
        <Link
          key={item.key}
          to={item.to}
          search={item.search}
          role="menuitem"
          aria-disabled={item.disabled ? true : undefined}
          className={cn(
            itemClass,
            item.destructive ? 'text-critical' : undefined,
            item.disabled ? 'pointer-events-none opacity-50' : undefined,
          )}
        >
          {content}
        </Link>
      )
    }
    if (item.href !== undefined) {
      return (
        <a
          key={item.key}
          href={item.href}
          role="menuitem"
          aria-disabled={item.disabled ? true : undefined}
          className={cn(
            itemClass,
            item.destructive ? 'text-critical' : undefined,
            item.disabled ? 'pointer-events-none opacity-50' : undefined,
          )}
        >
          {content}
        </a>
      )
    }
    return (
      <button
        key={item.key}
        type="button"
        role="menuitem"
        aria-disabled={item.disabled ? true : undefined}
        disabled={item.disabled}
        onClick={item.onSelect}
        className={cn(
          itemClass,
          item.destructive ? 'text-critical' : undefined,
          item.disabled ? 'pointer-events-none opacity-50' : undefined,
        )}
      >
        {content}
      </button>
    )
  }

  return (
    <span className="inline-flex">
      <button
        ref={(node) => {
          button.current = node
          if (triggerRef !== undefined) triggerRef.current = node
        }}
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => {
          if (open) {
            close(true)
          } else {
            setOpen(true)
          }
        }}
        onKeyDown={(event) => {
          if (event.key === 'Escape' && open) {
            close(true)
          }
          if (event.key === 'ArrowDown' && !open) {
            event.preventDefault()
            setOpen(true)
          }
        }}
        className={cn(
          'inline-flex size-7 items-center justify-center rounded-md text-[1rem] leading-none text-muted hover:bg-hover hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted',
          open ? 'bg-hover text-fg' : undefined,
          className,
        )}
      >
        <span aria-hidden="true">⋯</span>
      </button>

      {open
        ? createPortal(
            <div
              ref={menu}
              role="menu"
              aria-label={label}
              style={{
                top: position?.top ?? 0,
                left: position?.left ?? 0,
                visibility: position === null ? 'hidden' : 'visible',
              }}
              onClick={onMenuClick}
              onKeyDown={onKeyDown}
              className="fixed z-50 flex max-h-[min(28rem,calc(100vh-1rem))] min-w-[12rem] max-w-[16rem] flex-col overflow-y-auto rounded-md border border-border-strong bg-surface p-1 shadow-lg"
            >
              {items.map(renderItem)}

              {radios.map((group) => (
                <div
                  key={group.label}
                  role="group"
                  aria-label={group.label}
                  className="mt-1 flex flex-col border-t border-border-subtle pt-1"
                >
                  <div className="flex items-center gap-1 px-2 pb-1 pt-0.5 text-[0.75rem] text-faint">
                    <span className="flex-1">{group.title}</span>
                    {group.hint}
                  </div>
                  {group.options.map((option) => {
                    const checked = option.value === group.value
                    return (
                      <button
                        key={option.value}
                        type="button"
                        role="menuitemradio"
                        aria-checked={checked}
                        aria-disabled={group.disabled ? true : undefined}
                        disabled={group.disabled}
                        onClick={() => group.onChange(option.value)}
                        className={cn(
                          itemClass,
                          group.disabled
                            ? 'pointer-events-none opacity-50'
                            : undefined,
                        )}
                      >
                        <span aria-hidden="true" className="w-3 text-accent">
                          {checked ? '✓' : ''}
                        </span>
                        <span className="min-w-0 flex-1 truncate">{option.label}</span>
                      </button>
                    )
                  })}
                </div>
              ))}

              {trailingItems?.map(renderItem)}
            </div>,
            document.body,
          )
        : null}
    </span>
  )
}
