import { useQuery } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { ApiError } from '../api/client'
import {
  connectionsQuery,
  useCreateConnection,
  useDeleteConnection,
  useTestConnection,
  type Connection,
  type ConnectionStatus,
} from '../api/connections'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

/** statusView maps the API status to its badge text and tone. */
const statusView: Record<
  ConnectionStatus,
  { tone: 'ok' | 'critical' | 'neutral'; label: string }
> = {
  ok: { tone: 'ok', label: 'ok' },
  error: { tone: 'critical', label: 'error' },
  unknown: { tone: 'neutral', label: 'untested' },
}

export function ConnectionsPage() {
  const connections = useQuery(connectionsQuery)
  const github = (connections.data ?? []).filter(
    (connection) => connection.kind === 'github',
  )

  return (
    <>
      {connections.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">Loading connections…</p>
        </section>
      ) : null}

      {connections.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[13px] font-semibold">Connections failed to load</h2>
          <ErrorNote
            error={connections.error}
            fix="Restart bastion from the terminal and reload this page."
          />
        </section>
      ) : null}

      {connections.isSuccess && github.length === 0 ? (
        <EmptyState
          title="No GitHub connection yet"
          body="Bastion reads repositories with a read-only personal access token: a fine-grained token with Contents: read and Metadata: read, or a classic token with the repo scope for private repositories. The token is kept in the OS keychain, never in bastion's database, and is never shown again after you save it."
        >
          <a
            href="https://github.com/settings/personal-access-tokens/new"
            target="_blank"
            rel="noreferrer"
            className={buttonVariants()}
          >
            Create a fine-grained token
          </a>
          <span className="text-xs text-faint">
            GitHub → Settings → Developer settings → Personal access tokens
          </span>
        </EmptyState>
      ) : null}

      {github.length > 0 ? (
        <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 className="text-[13px] font-semibold">GitHub</h2>
            <span className="text-faint">Repositories bastion can read</span>
          </div>
          <ul className="flex flex-col divide-y divide-border-subtle">
            {github.map((connection) => (
              <ConnectionRow key={connection.id} connection={connection} />
            ))}
          </ul>
        </section>
      ) : null}

      <AddGitHubForm />

      <ComingSoonCard
        title="AWS"
        action="Connect AWS account"
        body="Reads ECR repositories and image tags through your existing AWS profile or SSO session. Bastion never stores AWS credentials; it uses the profile you already signed in with."
      />
      <ComingSoonCard
        title="Docker"
        action="Connect Docker"
        body="Scans images from a local Docker daemon, when one is running. Nothing is pulled or pushed without your action."
      />
    </>
  )
}

/** ConnectionRow is one GitHub connection with its test and remove actions. */
function ConnectionRow({ connection }: { connection: Connection }) {
  const test = useTestConnection()
  const remove = useDeleteConnection()
  const [confirming, setConfirming] = useState(false)
  const status = statusView[connection.status]

  return (
    <li className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{connection.name}</span>
        <Badge tone={status.tone}>{status.label}</Badge>
        {connection.login ? (
          <span className="font-mono text-xs text-muted">@{connection.login}</span>
        ) : null}
        <span className="text-xs text-faint">
          {lastCheckedLabel(connection.last_checked_at)}
        </span>

        {confirming ? null : (
          <div className="ml-auto flex items-center gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => test.mutate(connection.id)}
              disabled={test.isPending}
            >
              {test.isPending ? 'Testing…' : 'Test'}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                test.reset()
                setConfirming(true)
              }}
            >
              Remove
            </Button>
          </div>
        )}
      </div>

      {connection.status === 'error' && connection.hint ? (
        <p className="max-w-[70ch] text-xs text-muted">{connection.hint}</p>
      ) : null}

      {confirming ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
          <span>
            Remove “{connection.name}”? Its token is deleted from the OS keychain.
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="text-critical"
            onClick={() => remove.mutate(connection.id)}
            disabled={remove.isPending}
          >
            {remove.isPending ? 'Removing…' : 'Remove'}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => {
              remove.reset()
              setConfirming(false)
            }}
          >
            Cancel
          </Button>
        </div>
      ) : null}

      {test.isError ? (
        <ErrorNote
          error={test.error}
          fix="Test again; if it keeps failing, remove and re-add the connection."
        />
      ) : null}
      {remove.isError ? (
        <ErrorNote
          error={remove.error}
          fix="The token stays until removal succeeds; try again."
        />
      ) : null}
    </li>
  )
}

/** AddGitHubForm creates a connection; the server tests it before replying. */
function AddGitHubForm() {
  const create = useCreateConnection()
  const [name, setName] = useState('')
  const [token, setToken] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setNotice(null)
    create.mutate(
      { kind: 'github', name, token },
      {
        onSuccess: (connection) => {
          setName('')
          setNotice(
            connection.status === 'ok'
              ? {
                  tone: 'ok',
                  cause: `Connection added; GitHub authenticated as ${connection.login ?? 'your account'}.`,
                }
              : {
                  tone: 'warn',
                  cause: 'Connection saved, but the test failed.',
                  fix:
                    connection.hint ??
                    'Check the token scopes, then use Test to try again.',
                },
          )
        },
        onError: (error) => setNotice({ tone: 'error', ...createErrorNote(error) }),
        // The token is never kept in the form after a submit, whatever happened.
        onSettled: () => setToken(''),
      },
    )
  }

  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex flex-col gap-0.5">
        <h2 className="text-[13px] font-semibold">Add GitHub connection</h2>
        <p className="text-xs text-muted">
          A read-only token is enough. It is stored in the OS keychain and never
          shown again.
        </p>
      </div>

      <div className="flex w-full max-w-3xl flex-wrap items-end gap-3">
        <div className="flex w-52 flex-col gap-1">
          <label htmlFor="github-name" className="text-xs font-medium text-muted">
            Name
          </label>
          <input
            id="github-name"
            name="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="off"
            placeholder="work"
            className={inputClass}
          />
        </div>

        <div className="flex min-w-64 flex-1 flex-col gap-1">
          <label htmlFor="github-token" className="text-xs font-medium text-muted">
            Personal access token
          </label>
          <input
            id="github-token"
            name="token"
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="github_pat_… or ghp_…"
            className={inputClass}
          />
        </div>

        <Button
          type="submit"
          disabled={create.isPending || name.trim() === '' || token.trim() === ''}
        >
          {create.isPending ? 'Adding…' : 'Add connection'}
        </Button>
      </div>

      <p className="text-xs text-faint">
        Tokens are never written to bastion's database, logged, or returned by the
        API.
      </p>

      {notice ? <NoticeLine notice={notice} /> : null}
    </form>
  )
}

/** ComingSoonCard is a disabled integration card (§8: AWS and Docker are P2). */
function ComingSoonCard({
  title,
  body,
  action,
}: {
  title: string
  body: string
  action: string
}) {
  return (
    <section
      aria-disabled="true"
      className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4 opacity-60"
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        <Badge>coming in v0.2</Badge>
      </div>
      <p className="max-w-[70ch] text-xs text-muted">{body}</p>
      <div>
        <Button type="button" size="sm" variant="outline" disabled>
          {action}
        </Button>
      </div>
    </section>
  )
}

type Notice = {
  tone: 'ok' | 'warn' | 'error'
  /** What happened, in the user's terms. */
  cause: string
  /** What to do next, when there is something to do. */
  fix?: string
}

/** NoticeLine shows the result of the last add attempt. */
function NoticeLine({ notice }: { notice: Notice }) {
  const color =
    notice.tone === 'ok'
      ? 'text-ok'
      : notice.tone === 'warn'
        ? 'text-high'
        : 'text-critical'

  return (
    <div
      role={notice.tone === 'error' ? 'alert' : 'status'}
      className="flex flex-col gap-0.5 text-xs"
    >
      <span className={color}>{notice.cause}</span>
      {notice.fix ? <span className="text-muted">{notice.fix}</span> : null}
    </div>
  )
}

/** ErrorNote shows a failed request with a human cause and a suggested fix. */
function ErrorNote({ error, fix }: { error: unknown; fix: string }) {
  const cause =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : 'the request failed'

  return (
    <p role="alert" className="text-xs text-critical">
      {cause} <span className="text-muted">{fix}</span>
    </p>
  )
}

/** createErrorNote turns a failed POST into cause plus fix (§7). */
function createErrorNote(error: unknown): { cause: string; fix: string } {
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return {
        cause: 'A GitHub connection with that name already exists.',
        fix: 'Pick a different name.',
      }
    }
    if (error.status === 400) {
      return {
        cause: error.message,
        fix: 'Check the name and token, then try again.',
      }
    }
    return {
      cause: error.message,
      fix: 'Try again; if it persists, check the terminal running bastion.',
    }
  }
  return {
    cause: error instanceof Error ? error.message : 'the request failed',
    fix: 'Try again.',
  }
}

/** lastCheckedLabel formats the last test time, or says it never ran. */
function lastCheckedLabel(timestamp: string | undefined): string {
  if (!timestamp) {
    return 'never tested'
  }
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return 'never tested'
  }
  return `tested ${dateTimeFormat.format(date)}`
}
