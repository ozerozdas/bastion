import { useEffect, useRef, type KeyboardEvent, type RefObject } from 'react'

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

/** trapTab keeps Tab and Shift+Tab inside the panel while it is open. */
function trapTab(event: KeyboardEvent<HTMLElement>, container: HTMLElement) {
  if (event.key !== 'Tab') return

  const items = Array.from(
    container.querySelectorAll<HTMLElement>(focusableSelector),
  )
  if (items.length === 0) {
    event.preventDefault()
    container.focus()
    return
  }

  const first = items[0]
  const last = items[items.length - 1]
  const active = document.activeElement

  if (!container.contains(active)) {
    event.preventDefault()
    first.focus()
  } else if (event.shiftKey && (active === first || active === container)) {
    // The panel itself holds focus right after open, so Shift+Tab from there wraps too.
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && active === last) {
    event.preventDefault()
    first.focus()
  }
}

/**
 * useDrawerFocus is the focus behaviour every side drawer shares (#90): focus
 * moves into the panel on open so Escape and Tab work at once, Tab is trapped,
 * and closing without a decision gives focus back to the row that opened it.
 */
export function useDrawerFocus(onClose: () => void): {
  panel: RefObject<HTMLDivElement | null>
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => void
} {
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null
    panel.current?.focus()
    return () => {
      if (opener?.isConnected) opener.focus()
    }
  }, [])

  return {
    panel,
    onKeyDown: (event) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onClose()
        return
      }
      if (panel.current) trapTab(event, panel.current)
    },
  }
}
