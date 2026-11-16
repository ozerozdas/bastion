import { formatNumber, t } from './i18n'

/** ordinal renders a percentile as an English ordinal: 92 → "92nd". */
export function ordinal(value: number): string {
  const rounded = Math.round(value)
  const mod100 = rounded % 100
  if (mod100 >= 11 && mod100 <= 13) {
    return `${String(rounded)}th`
  }
  switch (rounded % 10) {
    case 1:
      return `${String(rounded)}st`
    case 2:
      return `${String(rounded)}nd`
    case 3:
      return `${String(rounded)}rd`
    default:
      return `${String(rounded)}th`
  }
}

/**
 * percentileLabel is the percentile as the language writes it: "94th pct" in
 * English, "%94" in Turkish. Both the ordinal and the plain number are passed,
 * so a locale picks the one it uses.
 */
export function percentileLabel(value: number): string {
  return t('epss.percentile', {
    ordinal: ordinal(value),
    percent: formatNumber(Math.round(value)),
  })
}

/**
 * epssLabel is the one-line EPSS reading: "EPSS 0.94 · 94th pct". Percentile
 * comes from the feed as a fraction between 0 and 1.
 */
export function epssLabel(score: {
  score: number
  percentile: number
}): string {
  return t('epss.label', {
    score: formatNumber(score.score, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }),
    percentile: percentileLabel(score.percentile * 100),
  })
}
