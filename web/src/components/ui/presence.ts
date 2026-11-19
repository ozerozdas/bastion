import { useEffect, useRef, useState } from 'react'

/**
 * prefersReducedMotion mirrors the media query the motion tokens collapse
 * under, so a JS-timed exit never outlasts an animation that was turned off.
 */
export function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/**
 * usePresence keeps a conditionally rendered panel (a menu, a tooltip) mounted
 * for one exit duration after it closes, so its CSS exit can play before React
 * removes it. `closing` is the state the panel styles itself from; reopen it
 * within the exit window and the panel simply stays.
 *
 * The panel is mounted in the same render that opens it (the state adjustment
 * below runs during render), so a caller that measures its size in a layout
 * effect still measures a real element on first open.
 */
export function usePresence(
  open: boolean,
  exitMs: number,
): { mounted: boolean; closing: boolean } {
  const [mounted, setMounted] = useState(open)
  const [closing, setClosing] = useState(false)

  if (open && (!mounted || closing)) {
    setMounted(true)
    setClosing(false)
  }

  useEffect(() => {
    if (open || !mounted) return
    if (prefersReducedMotion()) {
      setMounted(false)
      return
    }
    setClosing(true)
    const timer = window.setTimeout(() => {
      setClosing(false)
      setMounted(false)
    }, exitMs)
    return () => window.clearTimeout(timer)
  }, [open, mounted, exitMs])

  return { mounted, closing }
}

/**
 * useDelayedClose is for overlays the parent mounts while they are open: the
 * close request turns `closing` on, and onClose runs one exit duration later,
 * so the panel and its scrim can animate out. Closing again while the exit is
 * playing is ignored. With reduced motion the parent is told at once.
 */
export function useDelayedClose(
  onClose: () => void,
  exitMs = 160,
): { close: () => void; closing: boolean } {
  const [closing, setClosing] = useState(false)
  const timer = useRef<number | undefined>(undefined)
  const callback = useRef(onClose)
  callback.current = onClose

  useEffect(
    () => () => {
      if (timer.current !== undefined) window.clearTimeout(timer.current)
    },
    [],
  )

  function close() {
    if (closing) return
    if (prefersReducedMotion()) {
      callback.current()
      return
    }
    setClosing(true)
    timer.current = window.setTimeout(() => callback.current(), exitMs)
  }

  return { close, closing }
}
