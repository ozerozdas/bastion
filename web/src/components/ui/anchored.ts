/**
 * anchoredPosition places a fixed-position panel next to the element that
 * opened it: below when the viewport has room, above when it does not, and
 * clamped inside the viewport so a tooltip near the edge is never cut off.
 * Panels are measured by the caller, so a long label wraps instead of
 * overflowing.
 */
export type AnchorAlign = 'start' | 'center' | 'end'

const margin = 8

export function anchoredPosition(
  trigger: DOMRect,
  panel: { width: number; height: number },
  { align = 'start', gap = 6 }: { align?: AnchorAlign; gap?: number } = {},
): { top: number; left: number } {
  const maxTop = window.innerHeight - panel.height - margin
  let top = trigger.bottom + gap
  if (top > maxTop) {
    const above = trigger.top - gap - panel.height
    top = above >= margin ? above : Math.max(margin, maxTop)
  }

  const rawLeft =
    align === 'center'
      ? trigger.left + trigger.width / 2 - panel.width / 2
      : align === 'end'
        ? trigger.right - panel.width
        : trigger.left
  const maxLeft = Math.max(margin, window.innerWidth - panel.width - margin)

  return {
    top: Math.max(margin, top),
    left: Math.min(Math.max(margin, rawLeft), maxLeft),
  }
}
