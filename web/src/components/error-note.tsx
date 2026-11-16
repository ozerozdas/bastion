import { ApiError } from '../api/client'
import { t, useT } from '../lib/i18n'

/** ErrorNote shows the problem detail the API returned (§7). */
export function ErrorNote({ error, fix }: { error: unknown; fix?: string }) {
  useT()
  const cause =
    error instanceof ApiError
      ? `${error.message}${error.problem?.title ? ` (${error.problem.title})` : ''}`
      : error instanceof Error
        ? error.message
        : t('common.requestFailed')

  return (
    <p role="alert" className="text-xs text-critical">
      {cause}{' '}
      <span className="text-muted">{fix ?? t('common.reloadFix')}</span>
    </p>
  )
}
