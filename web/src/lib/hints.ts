import { t } from './i18n'

/** suggestFix turns a scan error into a concrete next step (§7). */
export function suggestFix(error: string | undefined): string {
  const text = (error ?? '').toLowerCase()
  if (text.includes('token') || text.includes('401')) {
    return t('hints.token')
  }
  if (text.includes('rate limit')) {
    return t('hints.rateLimit')
  }
  if (text.includes('not found') || text.includes('404')) {
    return t('hints.notFound')
  }
  return t('hints.scans')
}
