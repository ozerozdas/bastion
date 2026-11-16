import { formatLocalDate } from './i18n'

/** ExpiryChoice is what the decision forms offer next to the state. */
export type ExpiryChoice = 'none' | '30' | '90' | 'date'

/**
 * expiryDate returns the ISO date (YYYY-MM-DD) `days` from today, which the API
 * reads as the end of that day (UTC).
 */
export function expiryDate(days: number): string {
  const date = new Date()
  date.setDate(date.getDate() + days)
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${String(date.getFullYear())}-${month}-${day}`
}

/**
 * expiryValue turns the form's choice into the request's expires_at: a date the
 * API extends to the end of the day. 'none' sends no expiry.
 */
export function expiryValue(choice: ExpiryChoice, day: string): string | undefined {
  if (choice === 'none') return undefined
  if (choice === 'date') return day === '' ? undefined : day
  return expiryDate(Number(choice))
}

/** expiryLabel renders a stored expiry as a short local date. */
export function expiryLabel(expiresAt: string): string {
  const parsed = new Date(expiresAt)
  if (Number.isNaN(parsed.getTime())) return expiresAt
  return formatLocalDate(parsed, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}
