import { useRef, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import { assetsQuery } from '../api/assets'
import {
  findingRulesQuery,
  useApproveFindingRule,
  useCreateFindingRule,
  useDeleteFindingRule,
  type CreateFindingRule,
  type FindingRule,
} from '../api/finding-rules'
import { useT } from '../lib/i18n'
import { ErrorNote } from './error-note'
import { ActionMenu } from './ui/action-menu'
import { Button, buttonVariants } from './ui/button'
import { InfoTip } from './ui/info-tip'

const fieldClass =
  'h-7 w-full rounded-md border border-border-strong bg-surface px-2 text-[0.6875rem] text-fg placeholder:text-faint'
const labelClass = 'flex flex-col gap-1 text-[0.6875rem] text-muted'

const findingTypes = ['vulnerability', 'secret', 'outdated', 'misconfig', 'license', 'sast'] as const

/** matcherText is the readable form of what a rule matches. */
function matcherText(rule: FindingRule) {
  return [rule.finding_type, rule.rule_id, rule.package_name, rule.path_glob]
    .filter(Boolean)
    .join(' · ')
}

/**
 * FindingRulesEditor is the noise rules card (#181): the suggestions an agent
 * proposed and the rules that are already closing findings, plus the add form
 * collapsed under a summary. Long explanation lives behind the info tip.
 */
export function FindingRulesEditor() {
  const t = useT()
  const rules = useQuery(findingRulesQuery)
  const assets = useQuery(assetsQuery)
  const create = useCreateFindingRule()
  const approve = useApproveFindingRule()
  const remove = useDeleteFindingRule()

  const [assetId, setAssetId] = useState('')
  const [findingType, setFindingType] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [packageName, setPackageName] = useState('')
  const [pathGlob, setPathGlob] = useState('')
  const [state, setState] = useState<CreateFindingRule['state']>('false_positive')
  const [reason, setReason] = useState('')
  const [expiresAt, setExpiresAt] = useState('')

  const hasMatcher = Boolean(findingType || ruleId.trim() || packageName.trim() || pathGlob.trim())
  const assetName = (id?: number) =>
    id === undefined
      ? t('settings.rules.allProjects')
      : (assets.data?.find((asset) => asset.id === id)?.display_name ?? t('asset.fallback', { id }))

  const submit = (event: FormEvent) => {
    event.preventDefault()
    create.mutate(
      {
        state,
        reason,
        ...(assetId ? { asset_id: Number(assetId) } : {}),
        ...(findingType ? { finding_type: findingType as CreateFindingRule['finding_type'] } : {}),
        ...(ruleId.trim() ? { rule_id: ruleId.trim() } : {}),
        ...(packageName.trim() ? { package_name: packageName.trim() } : {}),
        ...(pathGlob.trim() ? { path_glob: pathGlob.trim() } : {}),
        ...(expiresAt ? { expires_at: expiresAt } : {}),
      },
      {
        onSuccess: () => {
          dialog.current?.close()
          setRuleId('')
          setPackageName('')
          setPathGlob('')
          setReason('')
          setExpiresAt('')
        },
      },
    )
  }

  const proposed = rules.data?.rules.filter((rule) => rule.status === 'proposed') ?? []
  const active = rules.data?.rules.filter((rule) => rule.status !== 'proposed') ?? []
  const title = t('settings.rules.title')

  // ponytail: native <dialog> gives the focus trap, Escape and backdrop for free.
  const dialog = useRef<HTMLDialogElement>(null)

  return (
    <section
      aria-label={title}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-2">
        <h2 className="text-[0.9375rem] font-semibold">{title}</h2>
        <InfoTip
          label={t('settings.module.about', { title })}
          content={t('settings.rules.body')}
        />
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="ml-auto"
          onClick={() => dialog.current?.showModal()}
        >
          {t('settings.rules.addShort')}
        </Button>
      </div>

      {proposed.length > 0 ? (
        <div className="flex flex-col gap-1.5">
          <h3 className="text-[0.6875rem] font-semibold tracking-[0.08em] text-faint uppercase">
            {t('settings.rules.pending')}
          </h3>
          <ul className="flex flex-col gap-1.5">
            {proposed.map((rule) => (
              <li
                key={rule.id}
                // A suggestion waits on the user, so it stands out from the rules.
                className="flex flex-wrap items-start gap-2 rounded-md border border-high/40 border-l-[3px] border-l-high bg-high/5 px-2.5 py-2"
              >
                <RuleText rule={rule} assetName={assetName} />
                <div className="ml-auto flex shrink-0 gap-1">
                  <Button
                    type="button"
                    size="sm"
                    disabled={approve.isPending}
                    onClick={() => approve.mutate(rule.id)}
                  >
                    {t('settings.rules.approve')}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(rule.id)}
                  >
                    {t('settings.rules.reject')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="flex flex-col gap-1.5">
        <h3 className="text-[0.6875rem] font-semibold tracking-[0.08em] text-faint uppercase">
          {t('settings.rules.active')}
        </h3>
        {active.length === 0 ? (
          <p className="text-xs text-faint">{t('settings.rules.empty')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs whitespace-nowrap">
              <thead className="text-left text-faint">
                <tr className="border-b border-border-subtle">
                  <th className="py-1.5 pr-3 font-medium">#</th>
                  <th className="py-1.5 pr-3 font-medium">{t('settings.rules.match')}</th>
                  <th className="py-1.5 pr-3 font-medium">{t('settings.rules.project')}</th>
                  <th className="py-1.5 pr-3 font-medium">{t('settings.rules.reason')}</th>
                  <th className="py-1.5 pr-3 text-right font-medium">{t('settings.rules.closed')}</th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {active.map((rule) => (
                  <tr key={rule.id} className="border-b border-border-subtle last:border-0 hover:bg-hover">
                    <td className="py-1.5 pr-3 font-mono text-faint">{rule.id}</td>
                    <td className="py-1.5 pr-3 font-mono text-fg">{matcherText(rule)}</td>
                    <td className="py-1.5 pr-3 text-muted">{assetName(rule.asset_id)}</td>
                    <td className="max-w-[40ch] truncate py-1.5 pr-3 text-muted" title={rule.reason}>
                      {rule.reason}
                    </td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{rule.matched}</td>
                    <td className="py-0.5 text-right">
                      <ActionMenu
                        label={t('settings.rules.actions', { id: String(rule.id) })}
                        // ponytail: the shared "⋯" trigger, turned upright.
                        className="rotate-90"
                        items={[
                          {
                            key: 'delete',
                            label: t('settings.rules.delete'),
                            destructive: true,
                            disabled: remove.isPending,
                            onSelect: () => remove.mutate(rule.id),
                          },
                        ]}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <dialog
        ref={dialog}
        aria-label={t('settings.rules.addTitle')}
        // Clicking the backdrop lands on the dialog element itself.
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close()
        }}
        className="m-auto w-[min(560px,calc(100vw-2rem))] rounded-xl border border-border-subtle bg-surface p-5 text-fg shadow-xl backdrop:bg-black/40"
      >
        <div className="flex flex-col gap-4">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-[0.9375rem] font-semibold">{t('settings.rules.addTitle')}</h2>
            <button
              type="button"
              onClick={() => dialog.current?.close()}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              {t('common.close')}
            </button>
          </div>
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
          <label className={labelClass}>
            {t('settings.rules.project')}
            <select className={fieldClass} value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">{t('settings.rules.allProjects')}</option>
              {assets.data?.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.display_name}
                </option>
              ))}
            </select>
          </label>
          <label className={labelClass}>
            {t('settings.rules.type')}
            <select className={fieldClass} value={findingType} onChange={(e) => setFindingType(e.target.value)}>
              <option value="">{t('settings.rules.anyType')}</option>
              {findingTypes.map((kind) => (
                <option key={kind} value={kind}>
                  {t(`type.${kind}`)}
                </option>
              ))}
            </select>
          </label>
          <label className={labelClass}>
            {t('settings.rules.ruleId')}
            <input className={fieldClass} value={ruleId} maxLength={256} onChange={(e) => setRuleId(e.target.value)} />
          </label>
          <label className={labelClass}>
            {t('settings.rules.package')}
            <input className={fieldClass} value={packageName} maxLength={256} onChange={(e) => setPackageName(e.target.value)} />
          </label>
          <label className={labelClass}>
            {t('settings.rules.path')}
            <input
              className={fieldClass}
              value={pathGlob}
              maxLength={256}
              placeholder="*/tests/*"
              onChange={(e) => setPathGlob(e.target.value)}
            />
          </label>
          <label className={labelClass}>
            {t('settings.rules.state')}
            <select
              className={fieldClass}
              value={state}
              onChange={(e) => setState(e.target.value as CreateFindingRule['state'])}
            >
              <option value="false_positive">{t('state.false_positive')}</option>
              <option value="ignored">{t('state.ignored')}</option>
              <option value="accepted_risk">{t('state.accepted_risk')}</option>
            </select>
          </label>
          <label className={labelClass}>
            {t('settings.rules.reason')}
            <input
              className={fieldClass}
              value={reason}
              required
              maxLength={1000}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
          <label className={labelClass}>
            {t('settings.rules.expires')}
            <input
              type="date"
              className={fieldClass}
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </label>
          <div className="flex justify-end sm:col-span-2">
            <Button type="submit" size="sm" disabled={!hasMatcher || !reason.trim() || create.isPending}>
              {t('settings.rules.add')}
            </Button>
          </div>
        </form>
          {create.error ? <ErrorNote error={create.error} /> : null}
        </div>
      </dialog>

      {approve.error ? <ErrorNote error={approve.error} /> : null}
      {remove.error ? <ErrorNote error={remove.error} /> : null}
    </section>
  )
}

/** RuleText is a rule's matcher, scope and result, shared by both lists. */
function RuleText({
  rule,
  assetName,
}: {
  rule: FindingRule
  assetName: (id?: number) => string
}) {
  const t = useT()
  return (
    <div className="min-w-0 flex-1 text-xs">
      <p className="break-all font-mono text-fg">
        #{rule.id} {matcherText(rule)}
      </p>
      <p className="break-words text-muted">
        {assetName(rule.asset_id)} · {rule.reason}
      </p>
      <p className="text-faint">
        {rule.status === 'proposed'
          ? t('settings.rules.proposed')
          : t('settings.rules.matched', { count: rule.matched })}
      </p>
    </div>
  )
}
