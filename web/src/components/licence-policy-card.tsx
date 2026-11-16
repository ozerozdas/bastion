import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import {
  licencePolicyQuery,
  useSetLicencePolicy,
  type LicencePolicy,
} from '../api/licence-policy'
import { useT } from '../lib/i18n'
import { ErrorNote } from './error-note'
import { Button } from './ui/button'

const textareaClass =
  'min-h-16 w-full resize-y rounded-md border border-border-strong bg-surface px-2 py-1 font-mono text-[0.6875rem] text-fg placeholder:text-faint'

/**
 * LicencePolicyCard is one scope's licence policy (#39): an asset's policy next
 * to its findings. The global policy lives in the settings modal (#139).
 */
export function LicencePolicyCard({
  assetId,
  title,
}: {
  assetId?: number
  title?: string
}) {
  const t = useT()
  const { data } = useQuery(licencePolicyQuery(assetId))
  const heading = title ?? t('licence.title')

  if (!data) {
    return null
  }

  return (
    <section
      aria-label={heading}
      className="flex flex-col gap-1 rounded-lg border border-border-subtle bg-surface p-2.5"
    >
      <p className="text-xs font-medium">{heading}</p>
      <LicencePolicyEditor assetId={assetId} policy={data} />
    </section>
  )
}

/**
 * LicencePolicyEditor is the allow/deny form and its current counts, shared by
 * the per-asset card and the global policy in the settings modal. Allowed
 * licences are hidden; denied ones stay visible at high severity. The input is
 * one licence per line (commas also work); no extra dependency is needed.
 */
export function LicencePolicyEditor({
  assetId,
  policy,
  description,
}: {
  assetId?: number
  policy: LicencePolicy
  description?: string
}) {
  const t = useT()
  const save = useSetLicencePolicy(assetId)
  const [editing, setEditing] = useState(false)
  const [allow, setAllow] = useState('')
  const [deny, setDeny] = useState('')
  const allowId = useId()
  const denyId = useId()
  const editButton = useRef<HTMLButtonElement>(null)
  const wasEditing = useRef(false)

  // Leaving the form unmounts the focused control; without this, Escape would
  // stop reaching the dialog (or the page) after a save or cancel.
  useEffect(() => {
    if (wasEditing.current && !editing) {
      editButton.current?.focus()
    }
    wasEditing.current = editing
  }, [editing])

  function startEditing() {
    setAllow(policy.allow.join('\n'))
    setDeny(policy.deny.join('\n'))
    setEditing(true)
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    save.mutate(
      { allow: parseLicences(allow), deny: parseLicences(deny) },
      { onSuccess: () => setEditing(false) },
    )
  }

  const allowed = policy.allow.length
  const denied = policy.deny.length

  if (editing) {
    return (
      <form onSubmit={submit} className="flex flex-col gap-1.5">
        <label htmlFor={allowId} className="text-[0.6875rem] text-muted">
          {t('licence.allowed')}
        </label>
        <textarea
          id={allowId}
          aria-label={t('licence.allowed')}
          value={allow}
          onChange={(event) => setAllow(event.target.value)}
          placeholder={'MIT\nApache-2.0'}
          className={textareaClass}
        />
        <label htmlFor={denyId} className="text-[0.6875rem] text-muted">
          {t('licence.denied')}
        </label>
        <textarea
          id={denyId}
          aria-label={t('licence.denied')}
          value={deny}
          onChange={(event) => setDeny(event.target.value)}
          placeholder={'GPL-3.0\nAGPL-3.0'}
          className={textareaClass}
        />
        <p className="text-[0.625rem] leading-relaxed text-faint">
          {t('licence.hint')}
        </p>
        <div className="flex flex-wrap items-center gap-1">
          <Button type="submit" size="sm" disabled={save.isPending}>
            {save.isPending ? t('licence.saving') : t('licence.save')}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => setEditing(false)}
            disabled={save.isPending}
          >
            {t('licence.cancel')}
          </Button>
        </div>
        {save.isError ? <ErrorNote error={save.error} /> : null}
      </form>
    )
  }

  return (
    <>
      <div className="flex items-start justify-between gap-2">
        <p className="text-[0.6875rem] text-muted tabular-nums">
          {allowed === 0 && denied === 0
            ? assetId === undefined
              ? t('licence.noRulesGlobal')
              : t('licence.noRulesAsset')
            : t('licence.counts', { allowed, denied })}
        </p>
        <button
          ref={editButton}
          type="button"
          onClick={startEditing}
          className="text-[0.6875rem] text-faint hover:text-fg"
        >
          {t('licence.edit')}
        </button>
      </div>
      <p className="text-[0.625rem] leading-relaxed text-faint">
        {description ?? t('licence.defaultDescription')}
      </p>
    </>
  )
}

/** parseLicences splits the textarea on lines and commas, dropping blanks. */
function parseLicences(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
}
