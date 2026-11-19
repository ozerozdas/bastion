/** eolSoonDays is how close an end-of-life date must be to warn: under 90 days. */
export const eolSoonDays = 90

const dayMs = 86_400_000

/** EolStatus is how a runtime's end-of-life date reads today. */
export type EolStatus = 'past' | 'soon' | 'ok' | 'unknown'

/** yyyyMmDd matches the API's date-only end-of-life dates. */
const yyyyMmDd = /^(\d{4})-(\d{2})-(\d{2})$/

/** utcDay parses a date-only string to midnight UTC, or null when malformed. */
function utcDay(value: string): number | null {
  const match = yyyyMmDd.exec(value)
  if (match === null) return null
  const day = Date.UTC(
    Number(match[1]),
    Number(match[2]) - 1,
    Number(match[3]),
  )
  return Number.isNaN(day) ? null : day
}

/**
 * eolStatus classifies an end-of-life date against today, in whole UTC days: a
 * date already behind us is `past`, one under 90 days away is `soon`, and the
 * rest is `ok`. A missing or malformed date is `unknown`. `now` is injectable
 * so the tests do not read the wall clock.
 */
export function eolStatus(
  eolDate: string | null,
  now = Date.now(),
): EolStatus {
  const end = eolDate === null ? null : utcDay(eolDate)
  if (end === null) return 'unknown'
  const today = Math.floor(now / dayMs) * dayMs
  if (end < today) return 'past'
  if (end - today < eolSoonDays * dayMs) return 'soon'
  return 'ok'
}

/**
 * eolDaysLeft is the whole days from today to the end-of-life date, or null
 * when the date is missing or malformed. A past date is negative.
 */
export function eolDaysLeft(
  eolDate: string | null,
  now = Date.now(),
): number | null {
  const end = eolDate === null ? null : utcDay(eolDate)
  if (end === null) return null
  const today = Math.floor(now / dayMs) * dayMs
  return Math.round((end - today) / dayMs)
}
