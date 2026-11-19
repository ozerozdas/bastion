import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import {
  useRef,
  useState,
  type ComponentType,
  type FormEvent,
  type ReactNode,
  type SVGProps,
} from 'react'

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
import {
  BitbucketIcon,
  ContainersIcon,
  GitHubIcon,
  GitLabIcon,
} from '../components/icons'
import { ActionMenu } from '../components/ui/action-menu'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { InfoTip } from '../components/ui/info-tip'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { formatLocalDate, t, useT } from '../lib/i18n'
import type { ConnectionsTab } from '../lib/urls'
import { cn } from '../lib/utils'

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

      {connections.isSuccess ? (
        <ul
          aria-label={t('connections.github.title')}
          className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
        >
          {github.map((connection) => (
            <ConnectionRow key={connection.id} connection={connection} />
          ))}
          <li>
            <AddConnectionCard providers={repositoryProviders}>
              {(close) => <AddGitHubForm onAdded={close} />}
            </AddConnectionCard>
          </li>
        </ul>
      ) : null}
    </>
  )
}

type Provider = {
  value: string
  label: string
  Icon: ComponentType<SVGProps<SVGSVGElement>>
  ready: boolean
}

/** Repository providers; only GitHub is wired, the rest show what is coming. */
const repositoryProviders: Provider[] = [
  { value: 'github', label: 'GitHub', Icon: GitHubIcon, ready: true },
  { value: 'gitlab', label: 'GitLab', Icon: GitLabIcon, ready: false },
  { value: 'bitbucket', label: 'Bitbucket', Icon: BitbucketIcon, ready: false },
]

/** Registry providers; Docker is detected, not added, so only AWS is here. */
const registryProviders: Provider[] = [
  { value: 'aws', label: 'AWS ECR', Icon: ContainersIcon, ready: true },
  { value: 'ghcr', label: 'GHCR', Icon: GitHubIcon, ready: false },
  { value: 'dockerhub', label: 'Docker Hub', Icon: ContainersIcon, ready: false },
  { value: 'gar', label: 'Google Artifact Registry', Icon: ContainersIcon, ready: false },
  { value: 'acr', label: 'Azure ACR', Icon: ContainersIcon, ready: false },
]

/** Common ECR regions for the region field; any other value can be typed. */
const awsRegions = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1',
  'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
  'eu-south-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
  'ap-southeast-1', 'ap-southeast-2', 'sa-east-1', 'me-central-1',
]

/**
 * AddConnectionCard is the dashed "new connection" tile; it opens the add
 * form in a dialog with a provider picker. children gets the close callback.
 */
function AddConnectionCard({
  providers,
  children,
}: {
  providers: Provider[]
  children: (close: () => void) => ReactNode
}) {
  const t = useT()
  // ponytail: native <dialog> gives the focus trap, Escape and backdrop for free.
  const dialog = useRef<HTMLDialogElement>(null)
  const title = t('connections.new')
  const close = () => dialog.current?.close()

  return (
    <>
      <button
        type="button"
        onClick={() => dialog.current?.showModal()}
        className="flex h-full min-h-24 w-full flex-col items-center justify-center gap-1 rounded-card border border-dashed border-border-strong p-4 text-muted transition-colors hover:bg-hover hover:text-fg"
      >
        <span aria-hidden="true" className="text-xl leading-none">
          +
        </span>
        <span className="text-[0.8125rem] font-medium">{title}</span>
      </button>
      <dialog
        ref={dialog}
        aria-label={title}
        // Clicking the backdrop lands on the dialog element itself.
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close()
        }}
        className="m-auto w-[min(560px,calc(100vw-2rem))] rounded-xl border border-border-subtle bg-surface p-5 text-fg shadow-xl backdrop:bg-black/40"
      >
        <div className="flex flex-col gap-4">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-[0.9375rem] font-semibold">{title}</h2>
            <button
              type="button"
              onClick={close}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              {t('common.close')}
            </button>
          </div>
          <div
            role="group"
            aria-label={t('connections.provider')}
            className="flex flex-wrap gap-1.5"
          >
            {providers.map((provider) => (
              <button
                key={provider.value}
                type="button"
                aria-pressed={provider.ready}
                disabled={!provider.ready}
                className={cn(
                  'flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[0.8125rem]',
                  provider.ready
                    ? 'border-accent bg-hover font-medium'
                    : 'border-border-subtle text-faint',
                )}
              >
                <provider.Icon className="size-4" />
                {provider.label}
                {provider.ready ? null : (
                  <Badge tone="neutral">{t('connections.soon')}</Badge>
                )}
              </button>
            ))}
          </div>
          {children(close)}
        </div>
      </dialog>
    </>
  )
}

/** CardHead is a connection card's top line: provider, status and menu. */
function CardHead({
  Icon,
  provider,
  badge,
  menu,
}: {
  Icon: ComponentType<SVGProps<SVGSVGElement>>
  provider: string
  badge: ReactNode
  menu?: ReactNode
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="flex items-center gap-1.5 text-xs font-medium text-muted">
        <Icon className="size-4 text-fg" />
        {provider}
      </span>
      {badge}
      {menu ? <div className="-my-1 -mr-1 ml-auto">{menu}</div> : null}
    </div>
  )
}

/**
 * StatusBadge is the card's status. A failed test keeps its hint behind the
 * badge: hovering or focusing "error" shows why, so the card stays short.
 */
function StatusBadge({
  connection,
  testing,
}: {
  connection: Connection
  testing: boolean
}) {
  const status = statusView[connection.status]
  const badge = (
    <Badge tone={status.tone}>
      {testing ? t('connections.testing') : t(status.labelKey)}
    </Badge>
  )
  if (connection.status !== 'error' || !connection.hint) return badge
  return (
    <InfoTip
      label={t('connections.errorDetail', { name: connection.name })}
      content={connection.hint}
      trigger={badge}
      className="size-auto rounded-sm"
    />
  )
}

/** Detail is one labelled value in a card's detail grid. */
function Detail({ label, value, mono = false }: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <>
      <dt className="text-faint">{label}</dt>
      <dd className={cn('truncate text-muted', mono && 'font-mono')} title={value}>
        {value}
      </dd>
    </>
  )
}

/** connectionMenu is the card's "⋮" menu: test, rename and remove. */
function connectionMenu(
  connection: Connection,
  test: ReturnType<typeof useTestConnection>,
  onRename: () => void,
  onRemove: () => void,
) {
  return (
    <ActionMenu
      label={t('connections.actions', { name: connection.name })}
      // ponytail: the shared "⋯" trigger, turned upright.
      className="rotate-90"
      items={[
        {
          key: 'test',
          label: t('connections.test'),
          disabled: test.isPending,
          onSelect: () => test.mutate(connection.id),
        },
        {
          key: 'rename',
          label: t('connections.rename'),
          onSelect: () => {
            test.reset()
            onRename()
          },
        },
        {
          key: 'remove',
          label: t('connections.remove'),
          destructive: true,
          onSelect: () => {
            test.reset()
            onRemove()
          },
        },
      ]}
    />
  )
}

/** RemoveConfirm is the in-card confirmation a removal waits on. */
function RemoveConfirm({
  message,
  remove,
  id,
  onCancel,
}: {
  message: string
  remove: ReturnType<typeof useDeleteConnection>
  id: number
  onCancel: () => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
      <span>{message}</span>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="text-critical"
        onClick={() => remove.mutate(id)}
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
          onCancel()
        }}
      >
        {t('connections.cancel')}
      </Button>
    </div>
  )
}

const cardClass =
  'flex h-full flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4'

/** RegistryPanel is §8's registry sources: AWS accounts and the local daemon. */
function RegistryPanel() {
  const t = useT()
  const connections = useQuery(connectionsQuery)
  const aws = (connections.data ?? []).filter(
    (connection) => connection.kind === 'aws',
  )

  return (
    <>
      {connections.isPending ? (
        <p className="text-muted">{t('connections.loading')}</p>
      ) : null}

      {connections.isError ? (
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('connections.failed')}
          </h2>
          <ErrorNote error={connections.error} fix={t('connections.errorFix')} />
        </section>
      ) : null}

      {connections.isSuccess && aws.length === 0 ? (
        <p className="max-w-[70ch] text-xs text-muted">
          {t('connections.aws.emptyBefore')}{' '}
          <span className="font-mono">~/.aws/config</span>
          {t('connections.aws.emptyAfter')}
        </p>
      ) : null}

      <ul
        aria-label={t('connections.tabs.registry')}
        className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
      >
        <li>
          <DockerCard />
        </li>
        {aws.map((connection) => (
          <AWSConnectionRow key={connection.id} connection={connection} />
        ))}
        <li>
          <AddConnectionCard providers={registryProviders}>
            {(close) => <AddAWSForm onAdded={close} />}
          </AddConnectionCard>
        </li>
      </ul>
    </>
  )
}

/** AWSConnectionRow is one AWS connection card with its "⋮" menu. */
function AWSConnectionRow({ connection }: { connection: Connection }) {
  const t = useT()
  const test = useTestConnection()
  const remove = useDeleteConnection()
  const [confirming, setConfirming] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const archived = connection.ecr_asset_count
  const archiveWarning =
    archived > 0
      ? t('connections.aws.archiveWarning', { count: archived })
      : ''

  return (
    <li className={cardClass}>
      <CardHead
        Icon={ContainersIcon}
        provider={t('connections.aws.title')}
        badge={<StatusBadge connection={connection} testing={test.isPending} />}
        menu={
          confirming || renaming
            ? null
            : connectionMenu(
                connection,
                test,
                () => setRenaming(true),
                () => setConfirming(true),
              )
        }
      />
      {renaming ? (
        <RenameForm connection={connection} onDone={() => setRenaming(false)} />
      ) : (
        <span className="truncate text-[0.9375rem] font-semibold">
          {connection.name}
        </span>
      )}
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        {connection.region ? (
          <Detail label={t('connections.region')} value={connection.region} mono />
        ) : null}
        {connection.profile ? (
          <Detail label={t('connections.profile')} value={connection.profile} />
        ) : null}
        {connection.account ? (
          <Detail label={t('connections.account')} value={connection.account} mono />
        ) : null}
        {connection.arn ? (
          <Detail label="ARN" value={connection.arn} mono />
        ) : null}
      </dl>
      <span className="mt-auto pt-1 text-xs text-faint">
        {lastCheckedLabel(connection.last_checked_at)}
      </span>

      {confirming ? (
        <RemoveConfirm
          message={`${t('connections.aws.confirmRemove', { name: connection.name })}${archiveWarning ? ` ${archiveWarning}` : ''}`}
          remove={remove}
          id={connection.id}
          onCancel={() => setConfirming(false)}
        />
      ) : null}

      {test.isError ? (
        <ErrorNote error={test.error} fix={t('connections.aws.testErrorFix')} />
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
function AddAWSForm({ onAdded }: { onAdded: () => void }) {
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
          // A working connection shows up as its own card; close the dialog.
          if (connection.status === 'ok') onAdded()
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
    <form onSubmit={submit} className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        {t('connections.aws.addBodyBefore')}{' '}
        <span className="font-mono">aws sso login --profile work</span>
        {t('connections.aws.addBodyAfter')}
      </p>

      <div className="flex flex-col gap-1">
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

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1">
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

        <div className="flex flex-col gap-1">
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
            // ponytail: <datalist> is the combo box: pick a common region or type any.
            list="aws-regions"
            className={inputClass}
          />
          <datalist id="aws-regions">
            {awsRegions.map((region) => (
              <option key={region} value={region} />
            ))}
          </datalist>
        </div>
      </div>

      <div className="flex items-center justify-end gap-2">
        <InfoTip
          label={t('connections.aws.hintAria')}
          content={t('connections.aws.hint')}
        />
        <Button
          type="submit"
          disabled={
            create.isPending || name.trim() === '' || region.trim() === ''
          }
        >
          {create.isPending ? t('connections.adding') : t('connections.add')}
        </Button>
      </div>

      {notice ? <NoticeLine notice={notice} /> : null}
    </form>
  )
}

/**
 * DockerCard is the local daemon. It is detected, not added: with a daemon it
 * links to the Containers page, without one it stays as a muted card.
 */
function DockerCard() {
  const t = useT()
  const images = useQuery(dockerImagesQuery)
  const available = images.isSuccess && images.data.available

  return (
    <section className={cn(cardClass, available ? undefined : 'opacity-60')}>
      <CardHead
        Icon={ContainersIcon}
        provider={t('connections.docker.title')}
        badge={
          <Badge tone={available ? 'ok' : 'neutral'}>
            {available
              ? t('connections.docker.available')
              : t('connections.docker.unavailable')}
          </Badge>
        }
      />
      <h3 className="text-[0.9375rem] font-semibold">
        {t('connections.docker.local')}
      </h3>
      {available ? (
        <>
          <p className="text-xs text-muted">
            <span>
              {t('connections.docker.images', { count: images.data.images.length })}
            </span>
            {' · '}
            <span className="font-mono">{images.data.host}</span>
          </p>
          <div className="mt-auto pt-1">
            <Link
              to="/containers"
              className={buttonVariants({ size: 'sm', variant: 'outline' })}
            >
              {t('connections.docker.view')}
            </Link>
          </div>
        </>
      ) : (
        <p className="text-xs text-muted">{t('connections.docker.unavailableHint')}</p>
      )}
    </section>
  )
}

/** ConnectionRow is one GitHub connection card with its "⋮" menu. */
function ConnectionRow({ connection }: { connection: Connection }) {
  const test = useTestConnection()
  const remove = useDeleteConnection()
  const [confirming, setConfirming] = useState(false)
  const [renaming, setRenaming] = useState(false)

  return (
    <li className={cardClass}>
      <CardHead
        Icon={GitHubIcon}
        provider="GitHub"
        badge={<StatusBadge connection={connection} testing={test.isPending} />}
        menu={
          confirming || renaming
            ? null
            : connectionMenu(
                connection,
                test,
                () => setRenaming(true),
                () => setConfirming(true),
              )
        }
      />
      {renaming ? (
        <RenameForm connection={connection} onDone={() => setRenaming(false)} />
      ) : (
        <span className="truncate text-[0.9375rem] font-semibold">
          {connection.name}
        </span>
      )}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        {connection.login ? (
          <span className="font-mono text-xs text-muted">@{connection.login}</span>
        ) : null}
        <span className="text-xs text-faint">
          {lastCheckedLabel(connection.last_checked_at)}
        </span>
      </div>

      {confirming ? (
        <RemoveConfirm
          message={t('connections.github.confirmRemove', { name: connection.name })}
          remove={remove}
          id={connection.id}
          onCancel={() => setConfirming(false)}
        />
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
function AddGitHubForm({ onAdded }: { onAdded: () => void }) {
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
          // A working connection shows up as its own card; close the dialog.
          if (connection.status === 'ok') onAdded()
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
    <form onSubmit={submit} className="flex flex-col gap-3">
      {/* ponytail: native <details> is the collapse; no state needed. */}
      <details className="group rounded-md bg-hover px-3 py-1.5 text-xs">
        <summary className="flex cursor-pointer list-none items-center gap-1.5 font-medium [&::-webkit-details-marker]:hidden">
          <span
            aria-hidden="true"
            className="text-faint transition-transform group-open:rotate-90"
          >
            ›
          </span>
          {t('connections.github.perms.title')}
        </summary>
        <div className="flex flex-col gap-1.5 pt-1.5 pb-1">
        <ul className="flex flex-col gap-1 text-muted">
          <li>
            <span className="text-fg">{t('connections.github.perms.scan')}</span>{' '}
            <span className="font-mono">Contents: read · Metadata: read</span>
          </li>
          <li>
            <span className="text-fg">{t('connections.github.perms.pr')}</span>{' '}
            <span className="font-mono">Contents: write · Pull requests: write</span>
          </li>
          <li>{t('connections.github.perms.classic')}</li>
        </ul>
        <a
          href="https://github.com/settings/personal-access-tokens/new"
          target="_blank"
          rel="noreferrer"
          className="self-start underline underline-offset-2"
        >
          {t('connections.github.perms.create')}
        </a>
        </div>
      </details>

      <div className="flex w-full flex-col gap-3">
        <div className="flex flex-col gap-1">
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

        <div className="flex flex-col gap-1">
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

        <div className="flex items-center justify-end gap-2">
          <InfoTip
            label={t('connections.github.storageAria')}
            content={`${t('connections.github.addBody')} ${t('connections.github.addHint')}`}
          />
          <Button
            type="submit"
            disabled={create.isPending || name.trim() === '' || token.trim() === ''}
          >
            {create.isPending ? t('connections.adding') : t('connections.add')}
          </Button>
        </div>
      </div>

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
