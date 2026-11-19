import { useEffect, useRef, useState } from 'react'

import type { Asset } from '../api/assets'
import { useT } from '../lib/i18n'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { BranchIcon } from './icons'

/**
 * LinkRepositoryDialog is the confirm-before-apply repository picker: a search
 * box and a radio list keep even a long repository list inside the dialog,
 * instead of the row menu growing past the viewport. "No repository" clears
 * an existing link; the current link starts selected.
 */
export function LinkRepositoryDialog({
  name,
  repos,
  currentId,
  pending = false,
  onClose,
  onConfirm,
}: {
  /** The image's display name, used in the dialog's accessible name. */
  name: string
  repos: readonly Asset[]
  /** The linked repository's asset id, when there is one. */
  currentId: number | undefined
  pending?: boolean
  onClose: () => void
  /** undefined clears the link; a number links that repository. */
  onConfirm: (repoId: number | undefined) => void
}) {
  const t = useT()
  const dialog = useRef<HTMLDialogElement>(null)
  const [query, setQuery] = useState('')
  const [choice, setChoice] = useState(
    currentId === undefined ? '' : String(currentId),
  )

  useEffect(() => {
    const element = dialog.current
    if (element !== null && !element.open) element.showModal()
  }, [])

  const needle = query.trim().toLowerCase()
  const shown =
    needle === ''
      ? repos
      : repos.filter(
          (repo) =>
            repo.ref.toLowerCase().includes(needle) ||
            repo.display_name.toLowerCase().includes(needle),
        )
  const canApply =
    choice === '' ? currentId !== undefined : Number(choice) !== currentId
  const title = t('containers.link.aria', { name })

  return (
    <dialog
      ref={dialog}
      aria-labelledby="link-repository-title"
      onCancel={(event) => {
        event.preventDefault()
        onClose()
      }}
      onClose={onClose}
      onClick={(event) => {
        if (event.target === event.currentTarget) event.currentTarget.close()
      }}
      className="m-auto w-[min(520px,calc(100vw-2rem))] rounded-xl border border-border-subtle bg-surface p-5 text-fg shadow-xl backdrop:bg-black/40"
    >
      <div className="flex flex-col gap-4">
        <div className="flex items-start justify-between gap-3">
          <h2
            id="link-repository-title"
            className="text-[0.9375rem] font-semibold"
          >
            {title}
          </h2>
          <Button type="button" size="sm" variant="ghost" onClick={onClose}>
            {t('common.close')}
          </Button>
        </div>

        <label className="flex flex-col gap-1 text-xs text-muted">
          {t('containers.link.dialog.search')}
          <input
            type="search"
            value={query}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="owner/repo"
            onChange={(event) => setQuery(event.target.value)}
            className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
          />
        </label>

        <div
          role="radiogroup"
          aria-label={t('containers.link.aria', { name })}
          className="flex max-h-64 flex-col gap-0.5 overflow-y-auto rounded-md border border-border-subtle p-1"
        >
          <label className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[0.8125rem] hover:bg-hover">
            <input
              type="radio"
              name="link-repository"
              checked={choice === ''}
              onChange={() => setChoice('')}
              className="size-3.5 accent-accent"
            />
            <span className="flex-1 text-muted">
              {t('containers.link.dialog.none')}
            </span>
          </label>
          {shown.map((repo) => (
            <label
              key={repo.id}
              className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[0.8125rem] hover:bg-hover"
            >
              <input
                type="radio"
                name="link-repository"
                value={repo.id}
                checked={choice === String(repo.id)}
                onChange={() => setChoice(String(repo.id))}
                className="size-3.5 accent-accent"
              />
              <span
                className="min-w-0 flex-1 truncate font-mono"
                title={repo.ref}
              >
                {repo.display_name}
              </span>
              {repo.default_branch === undefined ? null : (
                <Badge className="max-w-[14ch]" title={repo.default_branch}>
                  <BranchIcon className="size-3 shrink-0" />
                  <span className="min-w-0 truncate font-mono">
                    {repo.default_branch}
                  </span>
                </Badge>
              )}
            </label>
          ))}
          {shown.length === 0 ? (
            <p className="px-2 py-1.5 text-xs text-faint">
              {t('containers.link.dialog.empty', { query: query.trim() })}
            </p>
          ) : null}
        </div>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            type="button"
            disabled={!canApply || pending}
            onClick={() => onConfirm(choice === '' ? undefined : Number(choice))}
          >
            {pending ? t('containers.link.linking') : t('containers.link.link')}
          </Button>
        </div>
      </div>
    </dialog>
  )
}
