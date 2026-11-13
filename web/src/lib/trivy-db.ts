import type { TrivyDBStatus } from '../api/trivy-db'

/** TrivyDBView is what the sidebar shows for one DB status. */
export type TrivyDBView =
  | { kind: 'hidden' }
  | { kind: 'missing' }
  | { kind: 'downloading'; fromScan: boolean }
  | { kind: 'failed'; error?: string }

/**
 * trivyDBView maps the API state onto the chip. No data (loading) and an error
 * both render nothing: a working DB and an unreachable API are not the user's
 * problem to fix from here.
 */
export function trivyDBView(status: TrivyDBStatus | undefined): TrivyDBView {
  switch (status?.state) {
    case 'missing':
      return { kind: 'missing' }
    case 'downloading':
      return { kind: 'downloading', fromScan: status.trigger === 'scan' }
    case 'failed':
      return { kind: 'failed', error: status.error }
    default:
      return { kind: 'hidden' }
  }
}
