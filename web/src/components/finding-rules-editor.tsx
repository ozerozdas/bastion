import { useState, type FormEvent } from 'react'
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
import { Button } from './ui/button'

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

/** FindingRulesEditor lists suppression rules, agent proposals and the add form (#181). */
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
          setRuleId('')
          setPackageName('')
          setPathGlob('')
          setReason('')
          setExpiresAt('')
        },
      },
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[0.6875rem] leading-relaxed text-muted">{t('settings.rules.body')}</p>

      {rules.data?.rules.length ? (
        <ul className="flex flex-col gap-2">
          {rules.data.rules.map((rule) => (
            <li key={rule.id} className="flex items-start justify-between gap-3 rounded-md bg-bg p-2">
              <div className="min-w-0 text-[0.6875rem]">
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
              <div className="flex shrink-0 gap-1">
                {rule.status === 'proposed' ? (
                  <Button
                    type="button"
                    size="sm"
                    disabled={approve.isPending}
                    onClick={() => approve.mutate(rule.id)}
                  >
                    {t('settings.rules.approve')}
                  </Button>
                ) : null}
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(rule.id)}
                >
                  {rule.status === 'proposed' ? t('settings.rules.reject') : t('settings.rules.delete')}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      <form onSubmit={submit} className="grid grid-cols-2 gap-2">
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
        <div className="col-span-2">
          <Button type="submit" size="sm" disabled={!hasMatcher || !reason.trim() || create.isPending}>
            {t('settings.rules.add')}
          </Button>
        </div>
      </form>
      {create.error ? <ErrorNote error={create.error} /> : null}
      {approve.error ? <ErrorNote error={approve.error} /> : null}
      {remove.error ? <ErrorNote error={remove.error} /> : null}
    </div>
  )
}
