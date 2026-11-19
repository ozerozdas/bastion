import type { SLAThresholds } from '../api/reports'

/** slaThresholdMin is the API's shortest allowed threshold, in days. */
export const slaThresholdMin = 1

/** slaThresholdMax is the API's longest allowed threshold, in days. */
export const slaThresholdMax = 3650

/** slaThresholdFields are the four severities a threshold exists for, in order. */
export const slaThresholdFields = [
  'critical',
  'high',
  'medium',
  'low',
] as const

/** SLAThresholdField is one severity with an editable threshold. */
export type SLAThresholdField = (typeof slaThresholdFields)[number]

/** SLAThresholdValues is the editor's raw input: one string per severity. */
export type SLAThresholdValues = Record<SLAThresholdField, string>

/** SLAThresholdErrors marks the fields whose input is not a valid day count. */
export type SLAThresholdErrors = Partial<Record<SLAThresholdField, true>>

/** SLAThresholdParse is either valid thresholds or the fields that failed. */
export type SLAThresholdParse =
  | { thresholds: SLAThresholds; errors: SLAThresholdErrors }
  | { thresholds: null; errors: SLAThresholdErrors }

/**
 * parseSlaThresholds turns the editor's strings into thresholds, rejecting
 * anything that is not a whole number of days in 1..3650. Every bad field is
 * reported at once, so the form can mark them all.
 */
export function parseSlaThresholds(values: SLAThresholdValues): SLAThresholdParse {
  const errors: SLAThresholdErrors = {}
  const numbers: Partial<Record<SLAThresholdField, number>> = {}

  for (const field of slaThresholdFields) {
    const raw = values[field].trim()
    const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN
    if (
      !Number.isInteger(value) ||
      value < slaThresholdMin ||
      value > slaThresholdMax
    ) {
      errors[field] = true
      continue
    }
    numbers[field] = value
  }

  const critical = numbers.critical
  const high = numbers.high
  const medium = numbers.medium
  const low = numbers.low
  if (
    critical === undefined ||
    high === undefined ||
    medium === undefined ||
    low === undefined
  ) {
    return { thresholds: null, errors }
  }

  return { thresholds: { critical, high, medium, low }, errors }
}

/** thresholdValues turns stored thresholds into the editor's initial strings. */
export function thresholdValues(thresholds: SLAThresholds): SLAThresholdValues {
  return {
    critical: String(thresholds.critical),
    high: String(thresholds.high),
    medium: String(thresholds.medium),
    low: String(thresholds.low),
  }
}
