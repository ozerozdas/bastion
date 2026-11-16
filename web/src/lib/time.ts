import type { Scan } from '../api/scans'
import { language, t } from './i18n'

/**
 * The formatters are cached per language: Intl construction is the expensive
 * part, and a language switch is rare.
 */
const dateTimeFormats = new Map<string, Intl.DateTimeFormat>()
const relativeFormats = new Map<string, Intl.RelativeTimeFormat>()

function dateTimeFormat(): Intl.DateTimeFormat {
  const code = language()
  let format = dateTimeFormats.get(code)
  if (format === undefined) {
    format = new Intl.DateTimeFormat(code, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
    dateTimeFormats.set(code, format)
  }
  return format
}

function relativeFormat(): Intl.RelativeTimeFormat {
  const code = language()
  let format = relativeFormats.get(code)
  if (format === undefined) {
    format = new Intl.RelativeTimeFormat(code, { numeric: 'auto' })
    relativeFormats.set(code, format)
  }
  return format
}

/**
 * relativeTime says when a timestamp was in one short unit, falling back to
 * the full date beyond a month. `now` is injectable so tests do not read the
 * wall clock.
 */
export function relativeTime(
  timestamp: string | undefined,
  now = Date.now(),
): string {
  if (!timestamp) {
    return t('time.notStarted')
  }
  const then = new Date(timestamp).getTime()
  if (Number.isNaN(then)) {
    return t('time.unknown')
  }
  const seconds = (then - now) / 1000
  const magnitude = Math.abs(seconds)
  if (magnitude < 45) {
    return t('time.justNow')
  }
  if (magnitude < 3600) {
    return relativeFormat().format(Math.round(seconds / 60), 'minute')
  }
  if (magnitude < 86_400) {
    return relativeFormat().format(Math.round(seconds / 3600), 'hour')
  }
  if (magnitude < 2_592_000) {
    return relativeFormat().format(Math.round(seconds / 86_400), 'day')
  }
  return formatDateTime(timestamp)
}

/** formatDateTime is the full timestamp shown on hover and for old scans. */
export function formatDateTime(timestamp: string): string {
  return dateTimeFormat().format(new Date(timestamp))
}

/** scanDuration is finished minus started, phrased in one short unit chain. */
export function scanDuration(
  scan: Pick<Scan, 'status' | 'started_at' | 'finished_at'>,
): string {
  if (!scan.started_at) {
    return scan.status === 'queued' ? t('time.waiting') : '—'
  }
  const started = new Date(scan.started_at).getTime()
  const finished = scan.finished_at ? new Date(scan.finished_at).getTime() : NaN
  if (Number.isNaN(started) || Number.isNaN(finished)) {
    return scan.status === 'running' ? t('time.running') : '—'
  }
  const seconds = Math.max(0, Math.round((finished - started) / 1000))
  if (seconds < 60) {
    return t('time.seconds', { seconds })
  }
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) {
    return t('time.minutes', { minutes, seconds: seconds % 60 })
  }
  const hours = Math.floor(minutes / 60)
  return t('time.hours', { hours, minutes: minutes % 60 })
}
