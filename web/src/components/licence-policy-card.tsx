import { useId, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import {
  licencePolicyQuery,
  useSetLicencePolicy,
} from '../api/licence-policy'
import { ErrorNote } from './error-note'
import { Button } from './ui/button'

const textareaClass =
  'min-h-16 w-full resize-y rounded-md border border-border-strong bg-surface px-2 py-1 font-mono text-[11px] text-fg placeholder:text-faint'

/**
 * LicencePolicyCard edits one scope's licence policy (#39): the global policy
 * in the sidebar, or an asset's policy next to its findings. Allowed licences
 * are hidden; denied ones stay visible at high severity. The input is one
 * licence per line (commas also work); no extra dependency is needed.
 */
export function LicencePolicyCard({
  assetId,
  title = 'Licence policy',
}: {
  assetId?: number
  title?: string
}) {
  const { data } = useQuery(licencePolicyQuery(assetId))
  const save = useSetLicencePolicy(assetId)
  const [editing, setEditing] = useState(false)
  const [allow, setAllow] = useState('')
  const [deny, setDeny] = useState('')
  const allowId = useId()
  const denyId = useId()

  if (!data && !editing) {
    return null
  }

  function startEditing() {
    setAllow((data?.allow ?? []).join('\n'))
    setDeny((data?.deny ?? []).join('\n'))
    setEditing(true)
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    save.mutate(
      { allow: parseLicences(allow), deny: parseLicences(deny) },
      { onSuccess: () => setEditing(false) },
    )
  }

  const allowed = data?.allow.length ?? 0
  const denied = data?.deny.length ?? 0

  return (
    <section
      aria-label={title}
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium">{title}</p>
        {editing ? null : (
          <button
            type="button"
            onClick={startEditing}
            className="text-[11px] text-faint hover:text-fg"
          >
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <form onSubmit={submit} className="flex flex-col gap-1.5">
          <label htmlFor={allowId} className="text-[11px] text-muted">
            Allowed licences
          </label>
          <textarea
            id={allowId}
            aria-label="Allowed licences"
            value={allow}
            onChange={(event) => setAllow(event.target.value)}
            placeholder={'MIT\nApache-2.0'}
            className={textareaClass}
          />
          <label htmlFor={denyId} className="text-[11px] text-muted">
            Denied licences
          </label>
          <textarea
            id={denyId}
            aria-label="Denied licences"
            value={deny}
            onChange={(event) => setDeny(event.target.value)}
            placeholder={'GPL-3.0\nAGPL-3.0'}
            className={textareaClass}
          />
          <p className="text-[10px] leading-relaxed text-faint">
            One licence per line. Allow hides it; deny raises it to high.
            Matches exactly as reported, so “MIT OR Apache-2.0” is its own
            entry.
          </p>
          <div className="flex flex-wrap items-center gap-1">
            <Button type="submit" size="sm" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : 'Save licence policy'}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => setEditing(false)}
              disabled={save.isPending}
            >
              Cancel
            </Button>
          </div>
          {save.isError ? <ErrorNote error={save.error} /> : null}
        </form>
      ) : (
        <>
          <p className="text-[11px] text-muted tabular-nums">
            {allowed === 0 && denied === 0
              ? assetId === undefined
                ? 'No rules. Licences are reported as scanned.'
                : 'No rules here. The global policy applies.'
              : `${String(allowed)} allowed · ${String(denied)} denied`}
          </p>
          <p className="text-[10px] leading-relaxed text-faint">
            Allow hides a licence; deny raises it to high.
          </p>
        </>
      )}
    </section>
  )
}

/** parseLicences splits the textarea on lines and commas, dropping blanks. */
function parseLicences(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
}
