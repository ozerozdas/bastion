import type { components } from './schema'

/** Problem is the RFC 9457 body every bastion error carries (§6). */
export type Problem = components['schemas']['Problem']

/** ApiError is a non-2xx response, with the parsed problem details when present. */
export class ApiError extends Error {
  readonly status: number
  readonly problem: Problem | undefined

  constructor(status: number, problem: Problem | undefined) {
    super(
      problem?.detail ??
        problem?.title ??
        `Request failed with status ${String(status)}`,
    )
    this.name = 'ApiError'
    this.status = status
    this.problem = problem
  }
}

/** CSRF_HEADER must accompany every mutating request (§4.3). */
const CSRF_HEADER = 'X-Bastion'

function isMutating(method: string): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
}

async function readProblem(response: Response): Promise<Problem | undefined> {
  if (!response.headers.get('Content-Type')?.startsWith('application/problem+json')) {
    return undefined
  }
  try {
    return (await response.json()) as Problem
  } catch {
    return undefined
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (isMutating(method)) {
    headers.set(CSRF_HEADER, '1')
  }
  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }

  // The session lives in an HttpOnly, SameSite=Strict cookie opened by the
  // startup token, so every request must be same-origin and carry cookies.
  const response = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: 'same-origin',
  })

  if (!response.ok) {
    throw new ApiError(response.status, await readProblem(response))
  }
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

/** api is the whole HTTP surface the UI needs: typed calls, one place for CSRF. */
export const api = {
  get: <T>(path: string): Promise<T> => request<T>(path),
  post: <T>(path: string, body: unknown): Promise<T> =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
}
