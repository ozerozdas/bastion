import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useState, type FormEvent } from 'react'

import { ApiError } from '../api/client'
import { dockerImagesQuery } from '../api/docker'
import {
  connectionsQuery,
  useCreateConnection,
  useDeleteConnection,
  useRenameConnection,
  useTestConnection,
  type Connection,
  type ConnectionStatus,
} from '../api/connections'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { InfoTip } from '../components/ui/info-tip'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { formatLocalDate, t, useT } from '../lib/i18n'
import type { ConnectionsTab } from '../lib/urls'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'

/** statusView maps the API status to its badge text and tone. */
const statusView: Record<
  ConnectionStatus,
  { tone: 'ok' | 'critical' | 'neutral'; labelKey: string }
> = {
  ok: { tone: 'ok', labelKey: 'connections.status.ok' },
  error: { tone: 'critical', labelKey: 'connections.status.error' },
  unknown: { tone: 'neutral', labelKey: 'connections.status.untested' },
}

export function ConnectionsPage() {
  const t = useT()
  const search = useSearch({ from: '/connections' })
  const navigate = useNavigate()
  const tab: ConnectionsTab = search.tab ?? 'repository'
  // connectionTabs are the two kinds of source (#107).
  const connectionTabs: TabItem<ConnectionsTab>[] = [
    { value: 'repository', label: t('connections.tabs.repository') },
    { value: 'registry', label: t('connections.tabs.registry') },
  ]

  return (
    <Tabs
      label={t('connections.tabs.aria')}
      items={connectionTabs}
      value={tab}
      onChange={(next) => {
        // The URL owns the tab, so a reload or a copied link lands on it.
        // replace: switching tabs is not a step the Back button should undo.
        void navigate({
          to: '/connections',
          search: next === 'registry' ? { tab: 'registry' } : {},
          replace: true,
        })
      }}
    >
      {tab === 'registry' ? <RegistryPanel /> : <RepositoryPanel />}
    </Tabs>
  )
}

/** RepositoryPanel is the GitHub source: the connections and their form. */
function RepositoryPanel() {
  const t = useT()
  const connections = useQuery(connectionsQuery)
  const github = (connections.data ?? []).filter(
    (connection) => connection.kind === 'github',
  )

  return (
    <>
      {connections.isPending ? (
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('connections.loading')}</p>
        </section>
      ) : null}

      {connections.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('connections.failed')}
          </h2>
          <ErrorNote error={connections.error} fix={t('connections.errorFix')} />
        </section>
      ) : null}

      {connections.isSuccess && github.length === 0 ? (
        <EmptyState
          title={t('connections.empty.title')}
          body={t('connections.empty.body')}
        >
          <a
            href="https://github.com/settings/personal-access-tokens/new"
            target="_blank"
            rel="noreferrer"
            className={buttonVariants()}
          >
            {t('connections.empty.action')}
          </a>
          <span className="text-xs text-faint">
            {t('connections.empty.hint')}
          </span>
        </EmptyState>
      ) : null}

      {github.length > 0 ? (
        <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 className="text-[0.8125rem] font-semibold">
              {t('connections.github.title')}
            </h2>
            <span className="text-faint">
              {t('connections.github.subtitle')}
            </span>
          </div>
          <ul className="flex flex-col divide-y divide-border-subtle">
            {github.map((connection) => (
              <ConnectionRow key={connection.id} connection={connection} />
            ))}
          </ul>
        </section>
      ) : null}

      <AddGitHubForm />
    </>
  )
}

/** RegistryPanel is §8's registry sources: AWS accounts and the local daemon. */
function RegistryPanel() {
  return (
    <>
      <AWSPanel />
      <AddAWSForm />
      <DockerPanel />
    </>
  )
}

/**
 * AWSPanel is the AWS source: the connections and the reminder that bastion
 * keeps no AWS credential of its own.
 */
function AWSPanel() {
  const t = useT()
  const connections = useQuery(connectionsQuery)
  const aws = (connections.data ?? []).filter(
    (connection) => connection.kind === 'aws',
  )

  return (
    <section className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4">
      <div className="flex flex-wrap items-baseline gap-2.5">
        <h2 className="text-[0.8125rem] font-semibold">
          {t('connections.aws.title')}
        </h2>
        <span className="text-faint">{t('connections.aws.subtitle')}</span>
      </div>

      {connections.isPending ? (
        <p className="text-muted">{t('connections.loading')}</p>
      ) : null}

      {connections.isError ? (
        <div className="flex flex-col gap-1">
          <h3 className="text-[0.8125rem] font-semibold">
            {t('connections.failed')}
          </h3>
          <ErrorNote error={connections.error} fix={t('connections.errorFix')} />
        </div>
      ) : null}

      {connections.isSuccess && aws.length === 0 ? (
        <p className="max-w-[70ch] text-xs text-muted">
          {t('connections.aws.emptyBefore')}{' '}
          <span className="font-mono">~/.aws/config</span>
          {t('connections.aws.emptyAfter')}
        </p>
      ) : null}

      {aws.length > 0 ? (
        <ul className="flex flex-col divide-y divide-border-subtle">
          {aws.map((connection) => (
            <AWSConnectionRow key={connection.id} connection={connection} />
          ))}
        </ul>
      ) : null}
    </section>
  )
}

/** AWSConnectionRow is one AWS connection with its test and remove actions. */
function AWSConnectionRow({ connection }: { connection: Connection }) {
  const t = useT()
  const test = useTestConnection()
  const remove = useDeleteConnection()
  const [confirming, setConfirming] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const status = statusView[connection.status]
  const archived = connection.ecr_asset_count
  const archiveWarning =
    archived > 0
      ? t('connections.aws.archiveWarning', { count: archived })
      : ''

  return (
    <li className="-mx-2 flex flex-col gap-2 rounded px-2 py-3 first:pt-0 last:pb-0 hover:bg-hover">
      <div className="flex flex-wrap items-center gap-2">
        {renaming ? (
          <RenameForm
            connection={connection}
            onDone={() => setRenaming(false)}
          />
        ) : (
          <span className="font-medium">{connection.name}</span>
        )}
        <Badge tone={status.tone}>{t(status.labelKey)}</Badge>
        {connection.region ? (
          <span className="font-mono text-xs text-muted">{connection.region}</span>
        ) : null}
        {connection.profile ? (
          <span className="text-xs text-muted">
            {t('connections.aws.profile', { name: connection.profile })}
          </span>
        ) : null}
        {connection.account ? (
          <span className="font-mono text-xs text-muted">
            {t('connections.aws.account', { account: connection.account })}
          </span>
        ) : null}
        <span className="text-xs text-faint">
          {lastCheckedLabel(connection.last_checked_at)}
        </span>

        {confirming || renaming ? null : (
          <div className="ml-auto flex items-center gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => test.mutate(connection.id)}
              disabled={test.isPending}
            >
              {test.isPending ? t('connections.testing') : t('connections.test')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                test.reset()
                setRenaming(true)
              }}
            >
              {t('connections.rename')}
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
              {t('connections.remove')}
            </Button>
          </div>
        )}
      </div>

      {connection.arn ? (
        <p className="break-all font-mono text-xs text-muted">{connection.arn}</p>
      ) : null}

      {connection.status === 'error' && connection.hint ? (
        <p className="max-w-[70ch] text-xs text-muted">{connection.hint}</p>
      ) : null}

      {confirming ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
          <span>
            {t('connections.aws.confirmRemove', { name: connection.name })}
            {archiveWarning ? ` ${archiveWarning}` : ''}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="text-critical"
            onClick={() => remove.mutate(connection.id)}
            disabled={remove.isPending}
          >
            {remove.isPending ? t('connections.removing') : t('connections.remove')}
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
            {t('connections.cancel')}
          </Button>
        </div>
      ) : null}

      {test.isError ? (
        <ErrorNote
          error={test.error}
          fix={t('connections.aws.testErrorFix')}
        />
      ) : null}
      {remove.isError ? (
        <ErrorNote
          error={remove.error}
          fix={t('connections.aws.removeErrorFix')}
        />
      ) : null}
    </li>
  )
}

/** AddAWSForm creates an AWS connection; the server tests it before replying. */
function AddAWSForm() {
  const t = useT()
  const create = useCreateConnection()
  const [name, setName] = useState('')
  const [profile, setProfile] = useState('')
  const [region, setRegion] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setNotice(null)
    create.mutate(
      { kind: 'aws', name, profile: profile.trim(), region },
      {
        onSuccess: (connection) => {
          setName('')
          setNotice(
            connection.status === 'ok'
              ? {
                  tone: 'ok',
                  cause: t('connections.aws.added', {
                    account: connection.account ?? t('health.unknown'),
                  }),
                }
              : {
                  tone: 'warn',
                  cause: t('connections.savedTestFailed'),
                  fix: connection.hint ?? t('connections.aws.checkFix'),
                },
          )
        },
        onError: (error) =>
          setNotice({ tone: 'error', ...createErrorNote(error, 'AWS') }),
      },
    )
  }

  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex flex-col gap-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('connections.aws.addTitle')}
          </h2>
          <InfoTip
            label={t('connections.aws.hintAria')}
            content={t('connections.aws.hint')}
          />
        </div>
        <p className="text-xs text-muted">
          {t('connections.aws.addBodyBefore')}{' '}
          <span className="font-mono">aws sso login --profile work</span>
          {t('connections.aws.addBodyAfter')}
        </p>
      </div>

      <div className="flex w-full max-w-3xl flex-wrap items-end gap-3">
        <div className="flex w-52 flex-col gap-1">
          <label htmlFor="aws-name" className="text-xs font-medium text-muted">
            {t('connections.name')}
          </label>
          <input
            id="aws-name"
            name="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="off"
            placeholder="prod"
            className={inputClass}
          />
        </div>

        <div className="flex w-56 flex-col gap-1">
          <label htmlFor="aws-profile" className="text-xs font-medium text-muted">
            {t('connections.profileOptional')}
          </label>
          <input
            id="aws-profile"
            name="profile"
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder={t('connections.profilePlaceholder')}
            className={inputClass}
          />
        </div>

        <div className="flex w-44 flex-col gap-1">
          <label htmlFor="aws-region" className="text-xs font-medium text-muted">
            {t('connections.region')}
          </label>
          <input
            id="aws-region"
            name="region"
            value={region}
            onChange={(event) => setRegion(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="eu-central-1"
            className={inputClass}
          />
        </div>

        <Button
          type="submit"
          disabled={
            create.isPending || name.trim() === '' || region.trim() === ''
          }
        >
          {create.isPending ? t('connections.adding') : t('connections.add')}
        </Button>
      </div>

      <p className="text-xs text-faint">{t('connections.aws.hint')}</p>

      {notice ? <NoticeLine notice={notice} /> : null}
    </form>
  )
}

/**
 * DockerPanel is a compact status card. Connections configures sources; the
 * image list and scans live on the Containers page. Without a daemon it
 * renders nothing: a machine without Docker is a normal state, not an error.
 */
function DockerPanel() {
  const t = useT()
  const images = useQuery(dockerImagesQuery)

  if (!images.isSuccess || !images.data.available) {
    return null
  }

  const count = images.data.images.length
  return (
    <section className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4">
      <div className="flex flex-wrap items-baseline gap-2.5">
        <h2 className="text-[0.8125rem] font-semibold">
          {t('connections.docker.title')}
        </h2>
        <Badge tone="ok">{t('connections.docker.available')}</Badge>
        <span className="text-faint">
          {t('connections.docker.images', { count })}
        </span>
      </div>
      <p className="text-xs text-muted">
        {t('connections.docker.reachedAt')}{' '}
        <span className="font-mono">{images.data.host}</span>
      </p>
      <div>
        <Link to="/containers" className={buttonVariants({ size: 'sm' })}>
          {t('connections.docker.view')}
        </Link>
      </div>
    </section>
  )
}

/** ConnectionRow is one GitHub connection with its test and remove actions. */
function ConnectionRow({ connection }: { connection: Connection }) {
  const test = useTestConnection()
  const remove = useDeleteConnection()
  const [confirming, setConfirming] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const status = statusView[connection.status]

  return (
    <li className="-mx-2 flex flex-col gap-2 rounded px-2 py-3 first:pt-0 last:pb-0 hover:bg-hover">
      <div className="flex flex-wrap items-center gap-2">
        {renaming ? (
          <RenameForm
            connection={connection}
            onDone={() => setRenaming(false)}
          />
        ) : (
          <span className="font-medium">{connection.name}</span>
        )}
        <Badge tone={status.tone}>{t(status.labelKey)}</Badge>
        {connection.login ? (
          <span className="font-mono text-xs text-muted">@{connection.login}</span>
        ) : null}
        <span className="text-xs text-faint">
          {lastCheckedLabel(connection.last_checked_at)}
        </span>

        {confirming || renaming ? null : (
          <div className="ml-auto flex items-center gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => test.mutate(connection.id)}
              disabled={test.isPending}
            >
              {test.isPending ? t('connections.testing') : t('connections.test')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                test.reset()
                setRenaming(true)
              }}
            >
              {t('connections.rename')}
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
              {t('connections.remove')}
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
            {remove.isPending ? t('connections.removing') : t('connections.remove')}
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
            {t('connections.cancel')}
          </Button>
        </div>
      ) : null}

      {test.isError ? (
        <ErrorNote
          error={test.error}
          fix={t('connections.github.testErrorFix')}
        />
      ) : null}
      {remove.isError ? (
        <ErrorNote
          error={remove.error}
          fix={t('connections.github.removeErrorFix')}
        />
      ) : null}
    </li>
  )
}

/**
 * RenameForm is the inline name editor both tabs use: Enter (or Save) commits,
 * Escape (or Cancel) reverts to the stored name. A blank or unchanged name just
 * closes the editor.
 */
function RenameForm({
  connection,
  onDone,
}: {
  connection: Connection
  onDone: () => void
}) {
  const t = useT()
  const rename = useRenameConnection()
  const [name, setName] = useState(connection.name)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmed = name.trim()
    if (trimmed === '' || trimmed === connection.name) {
      onDone()
      return
    }
    rename.mutate(
      { id: connection.id, name: trimmed },
      { onSuccess: onDone },
    )
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-1.5">
      <div className="w-52">
        <input
          aria-label={t('connections.renameInput')}
          value={name}
          onChange={(event) => setName(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              onDone()
            }
          }}
          autoComplete="off"
          autoFocus
          className={inputClass}
        />
      </div>
      <Button
        type="submit"
        size="sm"
        variant="outline"
        disabled={rename.isPending || name.trim() === ''}
      >
        {t('connections.save')}
      </Button>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        onClick={() => {
          rename.reset()
          onDone()
        }}
      >
        {t('connections.cancel')}
      </Button>
      {rename.isError ? (
        <span className="w-full">
          <ErrorNote
            error={rename.error}
            fix={t('connections.renameErrorFix')}
          />
        </span>
      ) : null}
    </form>
  )
}

/** AddGitHubForm creates a connection; the server tests it before replying. */
function AddGitHubForm() {
  const t = useT()
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
                  cause: t('connections.github.added', {
                    login: connection.login ?? t('connections.github.loginFallback'),
                  }),
                }
              : {
                  tone: 'warn',
                  cause: t('connections.savedTestFailed'),
                  fix: connection.hint ?? t('connections.github.checkFix'),
                },
          )
        },
        onError: (error) => setNotice({ tone: 'error', ...createErrorNote(error, 'GitHub') }),
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
        <h2 className="text-[0.8125rem] font-semibold">
          {t('connections.github.addTitle')}
        </h2>
        <p className="text-xs text-muted">{t('connections.github.addBody')}</p>
      </div>

      <div className="flex w-full max-w-3xl flex-wrap items-end gap-3">
        <div className="flex w-52 flex-col gap-1">
          <label htmlFor="github-name" className="text-xs font-medium text-muted">
            {t('connections.name')}
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
            {t('connections.github.token')}
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
          {create.isPending ? t('connections.adding') : t('connections.add')}
        </Button>
      </div>

      <p className="text-xs text-faint">{t('connections.github.addHint')}</p>

      {notice ? <NoticeLine notice={notice} /> : null}
    </form>
  )
}

/** Notice is the result of the last add attempt. */
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
        : t('common.requestFailed')

  return (
    <p role="alert" className="text-xs text-critical">
      {cause} <span className="text-muted">{fix}</span>
    </p>
  )
}

/** createErrorNote turns a failed POST into cause plus fix (§7). */
function createErrorNote(
  error: unknown,
  provider: 'GitHub' | 'AWS',
): { cause: string; fix: string } {
  const existsKey =
    provider === 'AWS'
      ? 'connections.create.exists.an'
      : 'connections.create.exists.a'
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return {
        cause: t(existsKey, { provider }),
        fix: t('connections.create.existsFix'),
      }
    }
    if (error.status === 400) {
      return {
        cause: error.message,
        fix:
          provider === 'AWS'
            ? t('connections.create.awsFix')
            : t('connections.create.githubFix'),
      }
    }
    return {
      cause: error.message,
      fix: t('connections.create.retryFix'),
    }
  }
  return {
    cause: error instanceof Error ? error.message : t('common.requestFailed'),
    fix: t('connections.create.tryAgain'),
  }
}

/** lastCheckedLabel formats the last test time, or says it never ran. */
function lastCheckedLabel(timestamp: string | undefined): string {
  if (!timestamp) {
    return t('connections.neverTested')
  }
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return t('connections.neverTested')
  }
  return t('connections.tested', {
    date: formatLocalDate(date, { dateStyle: 'medium', timeStyle: 'short' }),
  })
}
