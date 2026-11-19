import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useRouterState } from '@tanstack/react-router'

import { assetsQuery } from '../api/assets'
import {
  useClearFindingState,
  useSetFindingState,
  type Finding,
  type FindingState,
} from '../api/findings'
import { llmQuery, useExplainFinding } from '../api/llm'
import {
  severityLabel,
  severityTone,
  stateLabels,
  typeLabels,
} from '../lib/finding-labels'
import { expiryDate, expiryLabel, expiryValue, type ExpiryChoice } from '../lib/expiry'
import { epssLabel } from '../lib/epss'
import { useT } from '../lib/i18n'
import { isHttpsUrl } from '../lib/urls'
import { useDrawerFocus } from './drawer-focus'
import { ErrorNote } from './error-note'
import { MarkdownText } from './markdown-text'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { useDelayedClose } from './ui/presence'

const factsClass =
  'grid grid-cols-[7rem_1fr] items-baseline gap-x-3 gap-y-1.5 text-[0.8125rem]'
const referenceLimit = 5

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'

export type FindingDrawerProps = {
  finding: Finding
  onClose: () => void
  /**
   * onRemoving runs before a decision or reopen is sent. It cannot wait for
   * success: the refetch can drop the row and unmount this drawer first, and
   * then mutate's own callbacks never run.
   */
  onRemoving?: () => void
  /** onRemoveFailed undoes onRemoving when the request fails. */
  onRemoveFailed?: () => void
  /** readOnly hides the decision controls, e.g. for a finding a later scan fixed. */
  readOnly?: boolean
}

/**
 * FindingDrawer shows one finding's detail (§7.4). Scanner text is untrusted
 * (§4.3): the description is plain text and only https references become links.
 */
export function FindingDrawer({
  finding,
  onClose,
  onRemoving,
  onRemoveFailed,
  readOnly = false,
}: FindingDrawerProps) {
  const t = useT()
  // Closing slides the panel out before the parent unmounts it, so the exit is
  // still a transition the browser can run.
  const { close, closing } = useDelayedClose(onClose)
  const { panel, onKeyDown } = useDrawerFocus(close)
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const assets = useQuery(assetsQuery)
  const assetName =
    assets.data?.find((asset) => asset.id === finding.asset_id)?.display_name ??
    t('asset.fallback', { id: finding.asset_id })
  // On the project's own page this link would point at the page it is on.
  const showProject =
    finding.asset_id > 0 && pathname !== `/findings/${String(finding.asset_id)}`
  const setState = useSetFindingState()
  const clearState = useClearFindingState()
  const { data: llm } = useQuery(llmQuery)
  const explain = useExplainFinding()
  const [decision, setDecision] = useState<FindingState>('ignored')
  const [reason, setReason] = useState('')
  const [expiryChoice, setExpiryChoice] = useState<ExpiryChoice>('none')
  const [expiryDay, setExpiryDay] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [allReferences, setAllReferences] = useState(false)
  // ponytail: length is a rough stand-in for rendered height; good enough to decide on a toggle.
  const longDescription = (finding.description?.length ?? 0) > 600

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onRemoving?.()
    setState.mutate(
      {
        asset_id: finding.asset_id,
        fingerprint: finding.fingerprint,
        state: decision,
        reason: reason.trim(),
        expires_at: expiryValue(expiryChoice, expiryDay),
      },
      { onSuccess: close, onError: onRemoveFailed },
    )
  }

  const packageLabel =
    finding.package_name === undefined
      ? undefined
      : finding.package_version === undefined
        ? finding.package_name
        : `${finding.package_name}@${finding.package_version}`

  const stateLabel = finding.state ? t(stateLabels[finding.state]) : ''

  return (
    <div className="fixed inset-0 z-40" data-closing={closing ? '' : undefined}>
      <div
        aria-hidden="true"
        onClick={close}
        className="absolute inset-0 overlay-scrim"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="panel-side absolute inset-y-0 right-0 flex w-full max-w-[460px] flex-col gap-4 overflow-y-auto border-l border-border-subtle bg-surface p-5 shadow-xl focus:outline-none"
      >
        <div className="sticky -top-5 z-10 -mx-5 -mt-5 flex items-start gap-3 border-b border-border-subtle bg-surface px-5 pt-5 pb-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <h2 id="finding-title" className="text-[0.9375rem] font-semibold break-words">
              {finding.title}
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={severityTone[finding.severity]}>
                {severityLabel(finding.severity)}
              </Badge>
              <Badge>{t(typeLabels[finding.type])}</Badge>
              {finding.type === 'license' ? (
                <span className="text-xs text-faint">
                  {finding.licence_policy === 'deny'
                    ? t('finding.licence.denied')
                    : t('finding.licence.informational')}
                </span>
              ) : null}
              {finding.state ? (
                <Badge tone={finding.expired ? 'medium' : 'neutral'}>
                  {stateLabel}
                  {finding.expires_at === undefined
                    ? ''
                    : finding.expired
                      ? t('finding.state.expired', {
                          date: expiryLabel(finding.expires_at),
                        })
                      : t('finding.state.until', {
                          date: expiryLabel(finding.expires_at),
                        })}
                </Badge>
              ) : null}
            </div>
          </div>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="ml-auto shrink-0"
            onClick={close}
          >
            {t('finding.close')}
          </Button>
        </div>

        <dl className={factsClass}>
          {showProject ? (
            <>
              <dt className="text-muted">{t('finding.project')}</dt>
              <dd className="min-w-0">
                <Link
                  to="/findings/$assetId"
                  params={{ assetId: String(finding.asset_id) }}
                  onClick={close}
                  title={assetName}
                  className="block truncate hover:underline"
                >
                  {assetName}
                </Link>
              </dd>
            </>
          ) : null}

          {finding.rule_id ? (
            <>
              <dt className="text-muted">{t('finding.rule')}</dt>
              <dd className="font-mono text-xs break-all">{finding.rule_id}</dd>
            </>
          ) : null}

          {packageLabel ? (
            <>
              <dt className="text-muted">{t('finding.package')}</dt>
              <dd className="font-mono text-xs break-all">{packageLabel}</dd>
            </>
          ) : null}

          {finding.fixed_version ? (
            <>
              <dt className="text-muted">{t('finding.fixedIn')}</dt>
              <dd className="font-mono text-xs break-all">{finding.fixed_version}</dd>
            </>
          ) : (
            <>
              <dt className="text-muted">{t('finding.fix')}</dt>
              <dd className="text-xs text-muted">{t('finding.noFixedVersion')}</dd>
            </>
          )}

          {finding.location ? (
            <>
              <dt className="text-muted">{t('finding.location')}</dt>
              <dd className="font-mono text-xs break-all">{finding.location}</dd>
            </>
          ) : null}

          {finding.epss ? (
            <>
              <dt className="text-muted">{t('finding.epss')}</dt>
              <dd className="tabular-nums">
                {epssLabel(finding.epss)}
              </dd>
            </>
          ) : null}

          {finding.reachability ? (
            <>
              <dt className="text-muted">{t('finding.reachability')}</dt>
              <dd>
                <Badge
                  tone={
                    finding.reachability === 'reachable'
                      ? 'critical'
                      : finding.reachability === 'unreachable'
                        ? 'ok'
                        : 'neutral'
                  }
                >
                  {finding.reachability}
                </Badge>
              </dd>
            </>
          ) : null}

        </dl>

        {finding.description ? (
          <section className="flex flex-col gap-1.5">
            <div
              className={
                longDescription && !expanded
                  ? 'relative max-h-48 overflow-hidden [mask-image:linear-gradient(to_bottom,black_70%,transparent)]'
                  : undefined
              }
            >
              <MarkdownText source={finding.description} />
            </div>
            {longDescription ? (
              <button
                type="button"
                onClick={() => setExpanded((value) => !value)}
                className="self-start text-xs font-medium text-muted underline underline-offset-2 hover:text-fg"
              >
                {expanded ? t('finding.showLess') : t('finding.showMore')}
              </button>
            ) : null}
          </section>
        ) : (
          <p className="text-xs text-faint">{t('finding.noDescription')}</p>
        )}

        {llm?.enabled && llm.model !== '' ? (
          <section className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
            <div className="flex items-center gap-2">
              <h3 className="text-[0.8125rem] font-semibold">
                {t('finding.explain.title')}
              </h3>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="ml-auto"
                disabled={explain.isPending}
                onClick={() =>
                  explain.mutate({
                    assetId: finding.asset_id,
                    fingerprint: finding.fingerprint,
                  })
                }
              >
                {explain.isPending
                  ? t('finding.explain.pending')
                  : t('finding.explain.action')}
              </Button>
            </div>
            <p className="text-xs text-faint">{t('finding.explain.hint')}</p>
            {explain.isError ? <ErrorNote error={explain.error} /> : null}
            {explain.data ? (
              <>
                <MarkdownText source={explain.data.text} />
                <p className="text-[0.6875rem] text-faint">
                  {t('finding.explain.note', { model: explain.data.model })}
                </p>
              </>
            ) : null}
          </section>
        ) : null}

        {readOnly ? (
          <p className="rounded-md border border-border-subtle bg-bg p-3 text-xs text-muted">
            {t('finding.readOnly')}
          </p>
        ) : (
          <section className="flex flex-col gap-2 rounded-md border border-border-subtle bg-bg p-3">
            <h3 className="text-[0.8125rem] font-semibold">
              {t('finding.decision')}
            </h3>

            {finding.state && !finding.expired ? (
              <>
                <p className="text-xs text-muted">
                  {finding.reason
                    ? t('finding.markedReason', {
                        state: stateLabel,
                        reason: finding.reason,
                      })
                    : t('finding.marked', { state: stateLabel })}
                </p>
                {finding.decided_by === 'agent' ? (
                  <p className="text-xs text-faint">
                    {t('finding.decidedByAgent')}
                  </p>
                ) : null}
                {finding.rule_ref ? (
                  <p className="text-xs text-faint">
                    {t('finding.closedByRule', { id: finding.rule_ref })}
                  </p>
                ) : null}
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      onRemoving?.()
                      clearState.mutate(
                        {
                          fingerprint: finding.fingerprint,
                          assetId: finding.asset_id,
                        },
                        { onSuccess: close, onError: onRemoveFailed },
                      )
                    }}
                    disabled={clearState.isPending}
                  >
                    {clearState.isPending
                      ? t('finding.reopening')
                      : t('finding.reopen')}
                  </Button>
                  <span className="text-xs text-faint">
                    {t('finding.reopenHint')}
                  </span>
                </div>
                {clearState.isError ? <ErrorNote error={clearState.error} /> : null}
              </>
            ) : (
              <form onSubmit={submit} className="flex flex-col gap-2">
                {finding.expired ? (
                  <p className="text-xs text-muted">
                    {finding.expires_at === undefined
                      ? t('finding.expiredPrevious')
                      : t('finding.expiredPreviousOn', {
                          date: expiryLabel(finding.expires_at),
                        })}
                  </p>
                ) : null}
                <div className="flex flex-col gap-1">
                  <label
                    htmlFor="finding-decision"
                    className="text-xs font-medium text-muted"
                  >
                    {t('finding.hideAs')}
                  </label>
                  <select
                    id="finding-decision"
                    value={decision}
                    onChange={(event) => setDecision(event.target.value as FindingState)}
                    className={`${inputClass} w-56`}
                  >
                    <option value="ignored">{t('state.ignored')}</option>
                    <option value="accepted_risk">
                      {t('state.accepted_risk')}
                    </option>
                    <option value="false_positive">
                      {t('state.false_positive')}
                    </option>
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor="finding-expiry"
                    className="text-xs font-medium text-muted"
                  >
                    {t('finding.expires')}
                  </label>
                  <select
                    id="finding-expiry"
                    value={expiryChoice}
                    onChange={(event) =>
                      setExpiryChoice(event.target.value as ExpiryChoice)
                    }
                    className={`${inputClass} w-56`}
                  >
                    <option value="none">{t('findings.bulk.noExpiry')}</option>
                    <option value="30">{t('findings.bulk.in30')}</option>
                    <option value="90">{t('findings.bulk.in90')}</option>
                    <option value="date">{t('findings.bulk.pickDate')}</option>
                  </select>
                  {expiryChoice === 'date' ? (
                    <input
                      type="date"
                      aria-label={t('findings.bulk.expiryDate')}
                      required
                      min={expiryDate(0)}
                      value={expiryDay}
                      onChange={(event) => setExpiryDay(event.target.value)}
                      className={`${inputClass} w-56`}
                    />
                  ) : null}
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor="finding-reason"
                    className="text-xs font-medium text-muted"
                  >
                    {t('finding.reason')}
                  </label>
                  <textarea
                    id="finding-reason"
                    required
                    rows={3}
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder={t('finding.reasonPlaceholder')}
                    className="w-full rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-[0.8125rem] text-fg placeholder:text-faint"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="submit"
                    size="sm"
                    disabled={setState.isPending || reason.trim() === ''}
                  >
                    {setState.isPending
                      ? t('finding.saving')
                      : t('finding.save')}
                  </Button>
                  <span className="text-xs text-faint">
                    {t('finding.applies')}
                  </span>
                </div>
              </form>
            )}

            {setState.isError ? (
              <ErrorNote error={setState.error} fix={t('finding.errorFix')} />
            ) : null}
          </section>
        )}

        {finding.references.length > 0 ? (
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[0.8125rem] font-semibold">
              {t('finding.references')}{' '}
              <span className="font-normal text-faint tabular-nums">
                {finding.references.length}
              </span>
            </h3>
            <ul className="flex flex-col gap-1 text-xs">
              {(allReferences
                ? finding.references
                : finding.references.slice(0, referenceLimit)
              ).map((reference, index) => (
                <li key={`${String(index)}-${reference}`} className="break-all">
                  {isHttpsUrl(reference) ? (
                    <a
                      href={reference}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="underline underline-offset-2 hover:text-fg"
                    >
                      {reference}
                    </a>
                  ) : (
                    <span className="text-muted">{reference}</span>
                  )}
                </li>
              ))}
            </ul>
            {!allReferences && finding.references.length > referenceLimit ? (
              <button
                type="button"
                onClick={() => setAllReferences(true)}
                className="self-start text-xs font-medium text-muted underline underline-offset-2 hover:text-fg"
              >
                {t('finding.showAllReferences', { count: finding.references.length })}
              </button>
            ) : null}
          </section>
        ) : null}

        <details className="group text-[0.8125rem]">
          <summary className="cursor-pointer text-[0.8125rem] font-semibold select-none">
            {t('finding.technical')}
          </summary>
          <dl className={`${factsClass} mt-2`}>
            <dt className="text-muted">{t('finding.scanner')}</dt>
            <dd className="font-mono text-xs">
              {(finding.scanners?.length ? finding.scanners : [finding.scanner]).join(', ')}
            </dd>

            <dt className="text-muted">{t('finding.occurrences')}</dt>
            <dd className="tabular-nums">{finding.occurrences}</dd>

            {finding.first_seen_scan_id !== undefined ? (
              <>
                <dt className="text-muted">{t('finding.firstSeen')}</dt>
                <dd className="tabular-nums">
                  {t('finding.scanId', { id: finding.first_seen_scan_id })}
                </dd>
              </>
            ) : null}

            <dt className="text-muted">{t('finding.fingerprint')}</dt>
            <dd className="font-mono text-[0.6875rem] break-all text-muted">
              {finding.fingerprint}
            </dd>
          </dl>
        </details>
      </div>
    </div>
  )
}
