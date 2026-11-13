import { ApiError } from '../api/client'

/** ErrorNote shows the problem detail the API returned (§7). */
export function ErrorNote({ error, fix }: { error: unknown; fix?: string }) {
  const cause =
    error instanceof ApiError
      ? `${error.message}${error.problem?.title ? ` (${error.problem.title})` : ''}`
      : error instanceof Error
        ? error.message
        : 'the request failed'

  return (
    <p role="alert" className="text-xs text-critical">
      {cause}{' '}
      <span className="text-muted">
        {fix ?? 'Reload the page; if it persists, check the terminal running bastion.'}
      </span>
    </p>
  )
}
