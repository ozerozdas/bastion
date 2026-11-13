import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Fragment, useEffect, useRef, useState, type FormEvent } from 'react'

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
import {
  DataTable,
  DataTableRow,
  type DataTableColumn,
  type DataTableSelection,
} from '../components/data-table'
import { EmptyState } from '../components/empty-state'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { CountBadge, severityCounts } from '../components/severity-counts'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { suggestFix } from '../lib/hints'
import { relativeTime } from '../lib/time'
import type { ProjectsTab } from '../lib/urls'
import { ScansPanel } from './history'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint'

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

/**
 * projectColumns are the table headers; ProjectRow renders its own cells
 * because it owns the per-row mutations and inline detail rows.
 */
const projectColumns: DataTableColumn<Asset>[] = [
  { id: 'project', header: 'Project' },
  { id: 'kind', header: 'Kind', headerClassName: 'pl-3' },
  { id: 'ref', header: 'Ref', headerClassName: 'pl-3' },
  { id: 'last-scan', header: 'Last scan', headerClassName: 'pl-3' },
  { id: 'open-findings', header: 'Open findings', headerClassName: 'pl-3' },
  { id: 'actions', header: 'Actions', headerClassName: 'pl-3 text-right' },
]

/** projectTabs are the two views of §7's Projects section (#88). */
const projectTabs: TabItem<ProjectsTab>[] = [
  { value: 'projects', label: 'Projects' },
  { value: 'scans', label: 'Scans' },
]

/**
 * ProjectsPage is §7.3: the assets table and the scan list as two tabs, so a
 * scan history stays with the projects it belongs to (#88).
 */
export function ProjectsPage() {
  const search = useSearch({ from: '/projects' })
  const navigate = useNavigate()
  const tab: ProjectsTab = search.tab ?? 'projects'

  return (
    <Tabs
      label="Projects views"
      items={projectTabs}
      value={tab}
      onChange={(next) => {
        // The URL owns the tab, so a reload or a copied link lands on it.
        // replace: switching tabs is not a step the Back button should undo.
        void navigate({
          to: '/projects',
          search: next === 'scans' ? { tab: 'scans' } : {},
          replace: true,
        })
      }}
    >
      {tab === 'scans' ? <ScansPanel /> : <ProjectsPanel />}
    </Tabs>
  )
}

/** ProjectsPanel is §7.3: the assets table plus the add-project dialog. */
function ProjectsPanel() {
  const assets = useQuery(assetsQuery)
  const live = useScanEvents()
  const [adding, setAdding] = useState(false)
  const list = assets.data ?? []

  return (
    <>
      <section
        aria-labelledby="projects-heading"
        className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex flex-wrap items-baseline gap-2.5">
            <h2 id="projects-heading" className="text-[13px] font-semibold">
              Projects
            </h2>
            <span className="text-faint">
              Repositories and local paths bastion scans
            </span>
          </div>
          <Button type="button" size="sm" onClick={() => setAdding(true)}>
            Add project
          </Button>
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

        {assets.isSuccess && list.length === 0 ? (
          <ProjectsEmpty onAdd={() => setAdding(true)} />
        ) : null}

        {assets.isSuccess && list.length > 0 ? (
          <ProjectsTable assets={list} live={live} />
        ) : null}
      </section>

      <AddProjectDialog open={adding} onClose={() => setAdding(false)} />
    </>
  )
}

/** ProjectsEmpty points at both ways to create the first project (§7). */
function ProjectsEmpty({ onAdd }: { onAdd: () => void }) {
  return (
    <EmptyState
      title="No projects yet"
      body="Projects are the repositories and local paths you scan. Connect GitHub to search your repositories and add them in bulk, or add an absolute path to a directory on this machine. Scans run locally; source is never uploaded."
    >
      <Link to="/connections" className={buttonVariants()}>
        Connect GitHub
      </Link>
      <Button type="button" variant="outline" onClick={onAdd}>
        Add a local path
      </Button>
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

  const selection: DataTableSelection<Asset> = {
    all: {
      checked: allSelected,
      onChange: toggleAll,
      label: 'Select all projects',
    },
    row: (asset) => ({
      checked: selected.has(asset.id),
      onChange: () => toggle(asset.id),
      label: `Select ${asset.display_name}`,
      cellClassName: 'py-2 align-top',
    }),
    headerClassName: 'w-8',
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

      <DataTable
        rows={assets}
        columns={projectColumns}
        rowKey={(asset) => String(asset.id)}
        selection={selection}
        renderRow={(asset) => (
          <ProjectRow asset={asset} live={live.get(asset.id)} selection={selection} />
        )}
      />
    </>
  )
}

/** ProjectRow is one asset and its small set of actions. */
function ProjectRow({
  asset,
  live,
  selection,
}: {
  asset: Asset
  live: LiveScan | undefined
  /** The table's selection config, so the shared row keeps its checkbox. */
  selection: DataTableSelection<Asset>
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
      <DataTableRow selection={selection.row(asset)}>
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
            {severityCounts.map((severity) => (
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
              to="/findings"
              search={{ asset: asset.id }}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              View findings
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
      </DataTableRow>

      {confirming ? (
        <tr>
          <td colSpan={7} className="pb-2">
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-subtle bg-bg px-2.5 py-2 text-xs">
              <span>
                Remove “{asset.display_name}”? Its existing scans stay in the
                Scans tab.
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

/**
 * AddProjectDialog holds the add-project panel in a modal (#105). A native
 * <dialog> keeps focus trapped and closes on Escape without extra code, and a
 * successful add closes it by flipping `open` in the parent.
 */
function AddProjectDialog({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const element = dialog.current
    if (element === null) return
    if (open && !element.open) {
      element.showModal()
    } else if (!open && element.open) {
      element.close()
    }
  }, [open])

  return (
    <dialog
      ref={dialog}
      aria-labelledby="add-projects"
      onClose={onClose}
      className="m-auto w-[min(760px,92vw)] max-h-[90vh] overflow-y-auto rounded-card border border-border-subtle bg-surface p-0 text-fg backdrop:bg-black/40"
    >
      {open ? <AddProjects onDone={onClose} /> : null}
    </dialog>
  )
}

/** AddProjects is the dialog body: GitHub discovery plus a local path. */
function AddProjects({ onDone }: { onDone: () => void }) {
  const connections = useQuery(connectionsQuery)
  const github = (connections.data ?? []).filter(
    (connection) => connection.kind === 'github',
  )

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <h2 id="add-projects" className="text-[13px] font-semibold">
            Add projects
          </h2>
          <p className="text-xs text-muted">
            Repositories are read with a connection token. A local path is
            scanned in place; nothing is uploaded.
          </p>
        </div>
        <Button type="button" size="sm" variant="ghost" onClick={onDone}>
          Close
        </Button>
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

      {github.length > 0 ? (
        <DiscoverRepos connections={github} onAdded={onDone} />
      ) : null}

      <AddLocalPath onAdded={onDone} />
    </div>
  )
}

type AddError = {
  ref: string
  cause: string
  fix: string
}

/** DiscoverRepos searches one connection's repositories and adds the picks. */
function DiscoverRepos({
  connections,
  onAdded,
}: {
  connections: Connection[]
  onAdded: () => void
}) {
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

  // Discovery lists only the token owner's repos; a public repo of someone
  // else is added by typing its full name.
  const typedName = /^[\w.-]+\/[\w.-]+$/.test(search.trim()) ? search.trim() : ''

  async function addChosen(names = chosen.map((repo) => repo.full_name)) {
    if (names.length === 0) {
      return
    }
    setAdding(true)
    setResult(null)
    const errors: AddError[] = []
    const added: string[] = []

    // One request per repo keeps the per-repo error visible, which a single
    // bulk call could not do (§7).
    for (const fullName of names) {
      try {
        await create.mutateAsync({
          kind: 'repo',
          ref: fullName,
          connection_id: connection.id,
        })
        added.push(fullName)
      } catch (error) {
        errors.push({ ref: fullName, ...addErrorNote(error) })
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
    // Nothing left to decide when every pick was added, so the modal closes.
    if (added.length > 0 && errors.length === 0) {
      onAdded()
    }
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
            Search, or type any owner/repo
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

        {typedName && !repos.some((repo) => repo.full_name === typedName) ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => void addChosen([typedName])}
            disabled={adding}
          >
            Add {typedName}
          </Button>
        ) : null}
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
function AddLocalPath({ onAdded }: { onAdded: () => void }) {
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
          // The row is in the table behind the modal, so success closes it.
          onAdded()
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
  const step = live.scanner ?? (live.stage ? stageLabel(live.stage) : null)
  return step ? `· ${step}` : null
}

/** stageLabel spells out the one stage whose wire name does not read as a step. */
function stageLabel(stage: NonNullable<LiveScan['stage']>): string {
  return stage === 'wait_db' ? 'Waiting for vulnerability DB' : stage
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
