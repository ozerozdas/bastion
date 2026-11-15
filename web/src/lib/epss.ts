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
 * epssLabel is the one-line EPSS reading: "EPSS 0.94 · 94th pct". Percentile
 * comes from the feed as a fraction between 0 and 1.
 */
export function epssLabel(score: {
  score: number
  percentile: number
}): string {
  return `EPSS ${score.score.toFixed(2)} · ${ordinal(score.percentile * 100)} pct`
}
