import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Fragment, useState, type FormEvent } from 'react'

import { assetsQuery, useArchiveAsset, useCreateAsset, type Asset } from '../api/assets'
import { ApiError } from '../api/client'
import {
  connectionsQuery,
  discoverQuery,
  type Connection,
  type DiscoveredRepo,
} from '../api/connections'
import { useScanEvents, type LiveScan } from '../api/events'
import { scansQuery, useCancelScan, useStartScans, type Scan } from '../api/scans'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

/** statusView maps a scan status to its badge text and tone (§7.5). */
const statusView: Record<
  Scan['status'],
  { tone: 'neutral' | 'ok' | 'critical'; label: string }
> = {
  queued: { tone: 'neutral', label: 'queued' },
  running: { tone: 'neutral', label: 'running' },
  succeeded: { tone: 'ok', label: 'succeeded' },
  failed: { tone: 'critical', label: 'failed' },
  canceled: { tone: 'neutral', label: 'canceled' },
}

/** kindLabels names what each asset row is; images arrive in v0.2 (§8). */
const kindLabels: Record<Asset['kind'], string> = {
  repo: 'repo',
  path: 'path',
  image: 'image',
}

/** severities is the fixed order of the four open-finding counts. */
const severities: {
  key: keyof Asset['open_counts']
  tone: 'critical' | 'high' | 'medium' | 'low'
}[] = [
  { key: 'critical', tone: 'critical' },
  { key: 'high', tone: 'high' },
  { key: 'medium', tone: 'medium' },
  { key: 'low', tone: 'low' },
]

/** ProjectsPage is §7.3: the assets table plus the inline add panel. */
export function ProjectsPage() {
  const assets = useQuery(assetsQuery)
  const live = useScanEvents()
  const list = assets.data ?? []

  return (
    <>
      <section
        aria-labelledby="projects-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-baseline gap-2.5">
          <h2 id="projects-heading" className="text-[13px] font-semibold">
            Projects
          </h2>
          <span className="text-faint">
            Repositories and local paths bastion scans
          </span>
        </div>

        {assets.isPending ? (
          <p className="text-muted">Loading projects…</p>
        ) : null}

        {assets.isError ? (
          <div className="flex flex-col gap-1">
            <h3 className="text-[13px] font-semibold">Projects failed to load</h3>
            <ErrorNote
              error={assets.error}
              fix="Reload the page; if it persists, check the terminal running bastion."
            />
          </div>
        ) : null}

        {assets.isSuccess && list.length === 0 ? <ProjectsEmpty /> : null}

        {assets.isSuccess && list.length > 0 ? (
          <ProjectsTable assets={list} live={live} />
        ) : null}
      </section>

      <AddProjects />
    </>
  )
}

/** ProjectsEmpty points at both ways to create the first project (§7). */
function ProjectsEmpty() {
  return (
    <EmptyState
      title="No projects yet"
      body="Projects are the repositories and local paths you scan. Connect GitHub to search your repositories and add them in bulk, or add an absolute path to a directory on this machine. Scans run locally; source is never uploaded."
    >
      <Link to="/connections" className={buttonVariants()}>
        Connect GitHub
      </Link>
      <a href="#add-projects" className={buttonVariants({ variant: 'outline' })}>
        Add a local path
      </a>
    </EmptyState>
  )
}

/** ProjectsTable lists assets with scan, cancel, report and remove actions. */
function ProjectsTable({
  assets,
  live,
}: {
  assets: Asset[]
  live: Map<number, LiveScan>
}) {
  const start = useStartScans()
  const [selected, setSelected] = useState<Set<number>>(() => new Set())
  const selectedIds = assets
    .filter((asset) => selected.has(asset.id))
    .map((asset) => asset.id)
  const allSelected = assets.length > 0 && selectedIds.length === assets.length

  function toggle(id: number) {
    setSelected((previous) => {
      const next = new Set(previous)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(assets.map((asset) => asset.id)))
  }

  return (
    <>
      {selectedIds.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted">{selectedIds.length} selected</span>
          <Button
            type="button"
            size="sm"
            onClick={() =>
              start.mutate(selectedIds, {
                onSuccess: () => setSelected(new Set()),
              })
            }
            disabled={start.isPending}
          >
            {start.isPending ? 'Starting…' : `Scan selected (${selectedIds.length})`}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => setSelected(new Set())}
          >
            Clear
          </Button>
        </div>
      ) : null}

      {start.isError ? (
        <ErrorNote
          error={start.error}
          fix="Scan the projects one at a time to see which one failed."
        />
      ) : null}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead className="text-xs text-faint">
            <tr>
              <th className="w-8 pb-2">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleAll}
                  aria-label="Select all projects"
                  className="size-3.5 accent-accent"
                />
              </th>
              <th className="pb-2 font-medium">Project</th>
              <th className="pb-2 pl-3 font-medium">Kind</th>
              <th className="pb-2 pl-3 font-medium">Ref</th>
              <th className="pb-2 pl-3 font-medium">Last scan</th>
              <th className="pb-2 pl-3 font-medium">Open findings</th>
              <th className="pb-2 pl-3 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {assets.map((asset) => (
              <ProjectRow
                key={asset.id}
                asset={asset}
                live={live.get(asset.id)}
                selected={selected.has(asset.id)}
                onToggle={() => toggle(asset.id)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

/** ProjectRow is one asset and its small set of actions. */
function ProjectRow({
  asset,
  live,
  selected,
  onToggle,
}: {
  asset: Asset
  live: LiveScan | undefined
  selected: boolean
  onToggle: () => void
}) {
  const start = useStartScans()
  const cancel = useCancelScan()
  const archive = useArchiveAsset()
  const [confirming, setConfirming] = useState(false)

  const lastScan = asset.last_scan
  // A live event wins over the list row until the finished event refetches it.
  const liveActive = live?.status === 'queued' || live?.status === 'running'
  const status = liveActive && live ? live.status : lastScan?.status
  const running = status === 'queued' || status === 'running'

  // AssetLastScan has no error field, so read the failed scan's own row.
  const failedScan = useQuery({
    ...scansQuery(asset.id, 1),
    enabled: lastScan?.status === 'failed',
  })
  const failed = live?.status === 'failed' || lastScan?.status === 'failed'
  const scanError =
    live?.status === 'failed' ? live.error : failedScan.data?.[0]?.error

  return (
    <Fragment>
      <tr>
        <td className="py-2 align-top">
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggle}
            aria-label={`Select ${asset.display_name}`}
            className="size-3.5 accent-accent"
          />
        </td>
        <td className="max-w-[24ch] py-2 pr-3 align-top">
          <span className="block truncate font-medium" title={asset.display_name}>
            {asset.display_name}
          </span>
        </td>
        <td className="py-2 pl-3 align-top">
          <Badge>{kindLabels[asset.kind]}</Badge>
        </td>
        <td className="max-w-[28ch] py-2 pl-3 align-top">
          <span className="block truncate font-mono text-xs text-muted" title={asset.ref}>
            {asset.ref}
          </span>
          {asset.default_branch ? (
            <span className="text-xs text-faint">{asset.default_branch}</span>
          ) : null}
        </td>
        <td className="py-2 pl-3 align-top whitespace-nowrap">
          {status ? (
            <Badge tone={statusView[status].tone}>{statusView[status].label}</Badge>
          ) : (
            <Badge>never scanned</Badge>
          )}
          <span className="ml-2 text-xs text-faint">
            {scanWhen(lastScan, running)}
          </span>
          {liveActive && live ? (
            <span className="ml-1 text-xs text-muted">{liveDetail(live)}</span>
          ) : null}
        </td>
        <td className="py-2 pl-3 align-top">
          <span className="flex flex-wrap gap-1">
            {severities.map((severity) => (
              <CountBadge
                key={severity.key}
                count={asset.open_counts[severity.key]}
                tone={severity.tone}
                label={severity.key}
              />
            ))}
          </span>
        </td>
        <td className="py-2 pl-3 align-top">
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => start.mutate([asset.id])}
              disabled={start.isPending || running}
            >
              {start.isPending ? 'Queueing…' : 'Scan'}
            </Button>
            {running && lastScan ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => cancel.mutate(lastScan.scan_id)}
                disabled={cancel.isPending}
              >
                {cancel.isPending ? 'Canceling…' : 'Cancel'}
              </Button>
            ) : null}
            <Link
              to="/security-reports"
              search={{ asset: asset.id }}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              View report
            </Link>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                start.reset()
                setConfirming(true)
              }}
            >
              Remove
            </Button>
          </div>
        </td>
      </tr>

      {confirming ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
              <span>
                Remove “{asset.display_name}”? Its existing scans stay in Scan
                History.
              </span>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="text-critical"
                onClick={() => archive.mutate(asset.id)}
                disabled={archive.isPending}
              >
                {archive.isPending ? 'Removing…' : 'Remove'}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => {
                  archive.reset()
                  setConfirming(false)
                }}
              >
                Cancel
              </Button>
            </div>
          </td>
        </tr>
      ) : null}

      {failed ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <ScanFailure error={scanError} />
          </td>
        </tr>
      ) : null}

      {start.isError ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <ErrorNote
              error={start.error}
              fix="Scan again; if it keeps failing, check the terminal running bastion."
            />
          </td>
        </tr>
      ) : null}
      {cancel.isError ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <ErrorNote
              error={cancel.error}
              fix="Reload the page to see the scan's final status."
            />
          </td>
        </tr>
      ) : null}
      {archive.isError ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <ErrorNote
              error={archive.error}
              fix="The project stays until removal succeeds; try again."
            />
          </td>
        </tr>
      ) : null}
    </Fragment>
  )
}

/** CountBadge keeps severity colour on the badge and greys out zero counts. */
function CountBadge({
  count,
  tone,
  label,
}: {
  count: number
  tone: 'critical' | 'high' | 'medium' | 'low'
  label: string
}) {
  return (
    <Badge
      tone={tone}
      className={count === 0 ? 'tabular-nums opacity-40' : 'tabular-nums'}
      aria-label={`${String(count)} open ${label} findings`}
    >
      {count}
    </Badge>
  )
}

/**
 * ScanFailure shows the failed scan's own message plus a next step. The hint
 * is derived from the text, because the API keeps the scanner's wording.
 */
function ScanFailure({ error }: { error: string | undefined }) {
  return (
    <p className="flex flex-col gap-0.5 text-xs">
      <span className="text-critical">
        {error ?? 'The scan failed without an error message.'}
      </span>
      <span className="text-muted">{suggestFix(error)}</span>
    </p>
  )
}

/** suggestFix turns a scan error into a concrete next step (§7). */
function suggestFix(error: string | undefined): string {
  const text = (error ?? '').toLowerCase()
  if (text.includes('token') || text.includes('401')) {
    return 'Re-test the GitHub connection on Connections.'
  }
  if (text.includes('rate limit')) {
    return 'Wait until GitHub resets the rate limit, then scan again.'
  }
  if (text.includes('not found') || text.includes('404')) {
    return 'Check the token has access to this repository.'
  }
  return 'See Scan History for details.'
}

/** AddProjects is the inline panel: GitHub discovery plus a local path. */
function AddProjects() {
  const connections = useQuery(connectionsQuery)
  const github = (connections.data ?? []).filter(
    (connection) => connection.kind === 'github',
  )

  return (
    <section
      aria-labelledby="add-projects"
      className="flex flex-col gap-4 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex flex-col gap-0.5">
        <h2 id="add-projects" className="text-[13px] font-semibold">
          Add projects
        </h2>
        <p className="text-xs text-muted">
          Repositories are read with a connection token. A local path is scanned
          in place; nothing is uploaded.
        </p>
      </div>

      {connections.isPending ? (
        <p className="text-muted">Loading connections…</p>
      ) : null}

      {connections.isError ? (
        <ErrorNote
          error={connections.error}
          fix="Reload the page; if it persists, check the terminal running bastion."
        />
      ) : null}

      {connections.isSuccess && github.length === 0 ? (
        <p className="text-xs text-muted">
          No GitHub connection yet.{' '}
          <Link to="/connections" className="underline">
            Add one on Connections
          </Link>{' '}
          to pick repositories, or add a local path below.
        </p>
      ) : null}

      {github.length > 0 ? <DiscoverRepos connections={github} /> : null}

      <AddLocalPath />
    </section>
  )
}

type AddError = {
  ref: string
  cause: string
  fix: string
}

/** DiscoverRepos searches one connection's repositories and adds the picks. */
function DiscoverRepos({ connections }: { connections: Connection[] }) {
  const queryClient = useQueryClient()
  const create = useCreateAsset()
  const [connectionId, setConnectionId] = useState<number | undefined>(undefined)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const [adding, setAdding] = useState(false)
  const [result, setResult] = useState<{ added: number; errors: AddError[] } | null>(
    null,
  )

  const connection =
    connections.find((item) => item.id === connectionId) ?? connections[0]
  // ADR-005: GitHub is called only on user action, so listing waits for a click.
  const [requested, setRequested] = useState(false)
  const discover = useQuery({ ...discoverQuery(connection.id), enabled: requested })
  const repos = discover.data ?? []
  const needle = search.trim().toLowerCase()
  const shown =
    needle === ''
      ? repos
      : repos.filter((repo) => repo.full_name.toLowerCase().includes(needle))
  const chosen = shown.filter(
    (repo) => !repo.already_added && selected.has(repo.full_name),
  )

  function toggle(fullName: string) {
    setSelected((previous) => {
      const next = new Set(previous)
      if (next.has(fullName)) {
        next.delete(fullName)
      } else {
        next.add(fullName)
      }
      return next
    })
  }

  async function addChosen() {
    if (chosen.length === 0) {
      return
    }
    setAdding(true)
    setResult(null)
    const errors: AddError[] = []
    const added: string[] = []

    // One request per repo keeps the per-repo error visible, which a single
    // bulk call could not do (§7).
    for (const repo of chosen) {
      try {
        await create.mutateAsync({
          kind: 'repo',
          ref: repo.full_name,
          connection_id: connection.id,
        })
        added.push(repo.full_name)
      } catch (error) {
        errors.push({ ref: repo.full_name, ...addErrorNote(error) })
      }
    }

    setAdding(false)
    setResult({ added: added.length, errors })
    setSelected((previous) => {
      const next = new Set(previous)
      for (const fullName of added) {
        next.delete(fullName)
      }
      return next
    })
    // already_added is now stale for the repos that succeeded.
    void queryClient.invalidateQueries({
      queryKey: discoverQuery(connection.id).queryKey,
    })
  }

  return (
    <div className="flex flex-col gap-3 rounded-md border border-border-subtle bg-bg p-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex w-52 flex-col gap-1">
          <label
            htmlFor="discover-connection"
            className="text-xs font-medium text-muted"
          >
            GitHub connection
          </label>
          <select
            id="discover-connection"
            value={connection.id}
            onChange={(event) => setConnectionId(Number(event.target.value))}
            className={inputClass}
          >
            {connections.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex min-w-64 flex-1 flex-col gap-1">
          <label htmlFor="discover-search" className="text-xs font-medium text-muted">
            Search repositories
          </label>
          <input
            id="discover-search"
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="owner/repo"
            autoComplete="off"
            spellCheck={false}
            className={inputClass}
          />
        </div>

        <Button
          type="button"
          onClick={() => void addChosen()}
          disabled={adding || chosen.length === 0}
        >
          {adding ? 'Adding…' : `Add ${String(chosen.length)}`}
        </Button>
      </div>

      {!requested ? (
        <div>
          <Button type="button" variant="outline" onClick={() => setRequested(true)}>
            List repositories
          </Button>
        </div>
      ) : discover.isPending ? (
        <p className="text-muted">Loading repositories…</p>
      ) : null}

      {discover.isError ? (
        <ErrorNote
          error={discover.error}
          fix="Re-test the GitHub connection on Connections; the token may have expired or lost access."
        />
      ) : null}

      {discover.isSuccess ? (
        shown.length === 0 ? (
          <p className="text-xs text-muted">
            {needle === ''
              ? 'This connection can read no repositories.'
              : `No repositories match “${search.trim()}”.`}
          </p>
        ) : (
          <ul
            aria-label="Repositories"
            className="flex max-h-72 flex-col divide-y divide-border-subtle overflow-y-auto"
          >
            {shown.map((repo) => (
              <RepoOption
                key={repo.full_name}
                repo={repo}
                checked={selected.has(repo.full_name)}
                onToggle={() => toggle(repo.full_name)}
              />
            ))}
          </ul>
        )
      ) : null}

      {result ? (
        <div role="status" className="flex flex-col gap-1 text-xs">
          {result.added > 0 ? (
            <span className="text-ok">
              Added {result.added} {result.added === 1 ? 'project' : 'projects'}.
            </span>
          ) : null}
          {result.errors.length > 0 ? (
            <ul className="flex flex-col gap-1">
              {result.errors.map((item) => (
                <li key={item.ref}>
                  <span className="font-mono">{item.ref}</span>{' '}
                  <span className="text-critical">{item.cause}</span>{' '}
                  <span className="text-muted">{item.fix}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

/** RepoOption is one discovered repository; added ones stay visible but disabled. */
function RepoOption({
  repo,
  checked,
  onToggle,
}: {
  repo: DiscoveredRepo
  checked: boolean
  onToggle: () => void
}) {
  const id = `repo-${repo.full_name}`
  return (
    <li className="py-1.5 first:pt-0 last:pb-0">
      <label
        htmlFor={id}
        className={`flex items-center gap-2 text-[13px] ${
          repo.already_added ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'
        }`}
      >
        <input
          id={id}
          type="checkbox"
          checked={checked || repo.already_added}
          disabled={repo.already_added}
          onChange={onToggle}
          className="size-3.5 accent-accent"
        />
        <span className="truncate font-mono text-xs" title={repo.full_name}>
          {repo.full_name}
        </span>
        <span className="text-xs text-faint">{repo.default_branch}</span>
        {repo.private ? <Badge>private</Badge> : null}
        {repo.archived ? <Badge>archived</Badge> : null}
        {repo.already_added ? <Badge tone="ok">added</Badge> : null}
      </label>
    </li>
  )
}

/** AddLocalPath adds one directory on this machine as an asset. */
function AddLocalPath() {
  const create = useCreateAsset()
  const [path, setPath] = useState('')
  const [notice, setNotice] = useState<{
    tone: 'ok' | 'error'
    cause: string
    fix?: string
  } | null>(null)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const ref = path.trim()
    setNotice(null)
    create.mutate(
      { kind: 'path', ref },
      {
        onSuccess: () => {
          setPath('')
          setNotice({
            tone: 'ok',
            cause: 'Local path added. Press Scan on its row to run the first scan.',
          })
        },
        onError: (error) => setNotice({ tone: 'error', ...addErrorNote(error) }),
      },
    )
  }

  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-2 border-t border-border-subtle pt-3"
    >
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex min-w-64 flex-1 flex-col gap-1">
          <label htmlFor="asset-path" className="text-xs font-medium text-muted">
            Or add a local path
          </label>
          <input
            id="asset-path"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="/Users/me/src/hello"
            autoComplete="off"
            spellCheck={false}
            className={inputClass}
          />
        </div>
        <Button type="submit" disabled={create.isPending || path.trim() === ''}>
          {create.isPending ? 'Adding…' : 'Add path'}
        </Button>
      </div>
      <p className="text-xs text-faint">
        An absolute path to a directory on this machine; it is scanned in place.
      </p>

      {notice ? (
        <p
          role={notice.tone === 'error' ? 'alert' : 'status'}
          className={`flex flex-col gap-0.5 text-xs ${
            notice.tone === 'error' ? 'text-critical' : 'text-ok'
          }`}
        >
          <span>{notice.cause}</span>
          {notice.fix ? <span className="text-muted">{notice.fix}</span> : null}
        </p>
      ) : null}
    </form>
  )
}

/** addErrorNote turns a failed asset create into cause plus fix (§7). */
function addErrorNote(error: unknown): { cause: string; fix: string } {
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return {
        cause: 'That project is already added.',
        fix: 'Remove it first, or pick another one.',
      }
    }
    if (error.status === 400) {
      return {
        cause: error.message,
        fix: 'Check the reference; a path must be an absolute directory that exists.',
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

/** liveDetail names the scanner or stage the live event is on. */
function liveDetail(live: LiveScan): string | null {
  const step = live.scanner ?? live.stage
  return step ? `· ${step}` : null
}

/** scanWhen says when the last scan finished, or that it is still running. */
function scanWhen(lastScan: Asset['last_scan'], running: boolean): string {
  if (running) {
    return 'in progress'
  }
  if (!lastScan?.finished_at) {
    return ''
  }
  return relativeTime(lastScan.finished_at)
}

/** relativeTime formats a timestamp the same way Scan History does. */
function relativeTime(timestamp: string): string {
  const then = new Date(timestamp).getTime()
  if (Number.isNaN(then)) {
    return 'unknown'
  }
  const seconds = (then - Date.now()) / 1000
  const magnitude = Math.abs(seconds)
  if (magnitude < 45) {
    return 'just now'
  }
  if (magnitude < 3600) {
    return relativeFormat.format(Math.round(seconds / 60), 'minute')
  }
  if (magnitude < 86_400) {
    return relativeFormat.format(Math.round(seconds / 3600), 'hour')
  }
  if (magnitude < 2_592_000) {
    return relativeFormat.format(Math.round(seconds / 86_400), 'day')
  }
  return dateTimeFormat.format(new Date(then))
}
