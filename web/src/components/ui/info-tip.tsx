import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'

import { InfoIcon } from '../icons'
import { cn } from '../../lib/utils'
import { anchoredPosition } from './anchored'

/**
 * InfoTip is the small "i" that explains a dense value without adding a
 * paragraph: hovering, keyboard focus or a tap reveals the text, Escape closes
 * it, and it is rendered in a portal so a table's overflow never clips it.
 * The trigger keeps the text in aria-describedby while it is shown.
 */
export function InfoTip({
  label,
  content,
  trigger,
  className,
  menuControl = false,
}: {
  /** Accessible name of the button, e.g. "About scan schedules". */
  label: string
  /** The explanation; short text or a small list. */
  content: ReactNode
  /** Visible trigger content; the info glyph by default. */
  trigger?: ReactNode
  /** Extra classes for the trigger button. */
  className?: string
  /** Joins a menu's arrow-key cycle when this tip sits inside one. */
  menuControl?: boolean
}) {
  const id = useId()
  const button = useRef<HTMLButtonElement>(null)
  const tip = useRef<HTMLDivElement>(null)
  const [hovered, setHovered] = useState(false)
  const [focused, setFocused] = useState(false)
  const [pinned, setPinned] = useState(false)
  const [position, setPosition] = useState<{ top: number; left: number } | null>(
    null,
  )
  const open = hovered || focused || pinned

  // Measured after mount, so a long tip is flipped and clamped, not clipped.
  useLayoutEffect(() => {
    if (!open) return
    const triggerEl = button.current
    const tipEl = tip.current
    if (triggerEl === null || tipEl === null) return
    setPosition(
      anchoredPosition(triggerEl.getBoundingClientRect(), {
        width: tipEl.offsetWidth,
        height: tipEl.offsetHeight,
      }, { align: 'center' }),
    )
  }, [open])

  useEffect(() => {
    if (!open) return

    function close() {
      setHovered(false)
      setFocused(false)
      setPinned(false)
    }
    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node
      if (button.current?.contains(target) || tip.current?.contains(target)) {
        return
      }
      close()
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') close()
    }

    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    window.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('resize', close)
    }
  }, [open])

  return (
    <span className="inline-flex">
      <button
        ref={button}
        type="button"
        aria-label={label}
        aria-describedby={open ? id : undefined}
        data-menu-control={menuControl ? '' : undefined}
        onPointerEnter={(event) => {
          if (event.pointerType === 'mouse') setHovered(true)
        }}
        onPointerLeave={(event) => {
          if (event.pointerType === 'mouse') setHovered(false)
        }}
        // A tap toggles; a mouse click or Enter has the tip open already.
        onClick={(event) => {
          const pointerType =
            event.nativeEvent instanceof PointerEvent
              ? event.nativeEvent.pointerType
              : ''
          if (pointerType === 'touch' || pointerType === 'pen') {
            setPinned((shown) => !shown)
          }
        }}
        onFocus={(event) => {
          // A tap also focuses the button; only a keyboard focus opens the tip.
          setFocused(event.currentTarget.matches(':focus-visible'))
        }}
        onBlur={() => {
          setFocused(false)
          setPinned(false)
        }}
        onKeyDown={(event) => {
          // Escape closes the tip. In a menu it must not also close the menu,
          // but in a dialog the dialog's own handler still gets the key.
          if (event.key === 'Escape' && open) {
            if (menuControl) event.stopPropagation()
            setPinned(false)
            setFocused(false)
            setHovered(false)
          }
        }}
        className={cn(
          'inline-flex size-4 items-center justify-center rounded-full align-middle text-faint hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted',
          className,
        )}
      >
        {trigger ?? <InfoIcon className="size-3.5" />}
      </button>

      {open
        ? createPortal(
            <div
              ref={tip}
              id={id}
              role="tooltip"
              style={{
                top: position?.top ?? 0,
                left: position?.left ?? 0,
                visibility: position === null ? 'hidden' : 'visible',
              }}
              className="pointer-events-none fixed z-50 max-w-[18rem] rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-[0.75rem] leading-snug text-fg shadow-lg"
            >
              {content}
            </div>,
            document.body,
          )
        : null}
    </span>
  )
}
