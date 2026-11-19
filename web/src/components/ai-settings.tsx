import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { llmModelsQuery, llmQuery, useSetLLMSettings } from '../api/llm'
import { useT } from '../lib/i18n'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Checkbox } from './ui/checkbox'
import { InfoTip } from './ui/info-tip'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'
const labelClass = 'text-xs font-medium text-muted'

/** RefreshIcon is the small arrow the model list's refresh button shows. */
function RefreshIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="size-3.5"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9" />
      <path d="M13.5 2.5V5H11" />
    </svg>
  )
}

/**
 * AISettings is Configuration's AI tab: the loopback endpoint a local model
 * answers from and the model's name. The choices save together, so a half
 * configured endpoint never reaches a scan.
 */
export function AISettings() {
  const t = useT()
  const { data } = useQuery(llmQuery)
  const save = useSetLLMSettings()
  const [enabled, setEnabled] = useState(false)
  const [endpoint, setEndpoint] = useState('')
  const [model, setModel] = useState('')
  // The offered names follow the endpoint field, so an unsaved edit still gets
  // the right list; the server validates and defaults it exactly like a save.
  const models = useQuery(llmModelsQuery(endpoint))

  // Seed the form from the server; depend on the individual fields so an
  // unrelated save does not overwrite what the user is typing.
  useEffect(() => {
    if (!data) {
      return
    }
    setEnabled(data.enabled)
    setEndpoint(data.endpoint)
    setModel(data.model)
  }, [data?.enabled, data?.endpoint, data?.model])

  if (!data) {
    return null
  }

  const changed =
    enabled !== data.enabled ||
    endpoint.trim() !== data.endpoint ||
    model.trim() !== data.model

  return (
    <section
      aria-label={t('settings.ai.title')}
      className="flex w-full max-w-2xl flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-2">
        <h2 className="text-[0.9375rem] font-semibold">
          {t('settings.ai.title')}
        </h2>
        <Badge tone={data.enabled ? 'ok' : 'neutral'}>
          {data.enabled ? t('settings.badge.on') : t('settings.badge.off')}
        </Badge>
        <InfoTip
          label={t('settings.module.about', { title: t('settings.ai.title') })}
          content={t('settings.ai.body')}
        />
      </div>

      <label className="flex items-center gap-2 text-xs text-muted">
        <Checkbox
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
        />
        {t('settings.ai.enabled')}
      </label>

      <div className="flex flex-col gap-1">
        <label htmlFor="ai-endpoint" className={labelClass}>
          {t('settings.ai.endpoint')}
        </label>
        <input
          id="ai-endpoint"
          type="text"
          autoComplete="off"
          value={endpoint}
          placeholder={t('settings.ai.endpointPlaceholder')}
          onChange={(event) => setEndpoint(event.target.value)}
          className={inputClass}
        />
        <p className="text-[0.6875rem] text-faint">
          {t('settings.ai.endpointHint')}
        </p>
      </div>

      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between gap-2">
          <label htmlFor="ai-model" className={labelClass}>
            {t('settings.ai.model')}
          </label>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-6 px-1.5 text-faint"
            aria-label={t('settings.ai.modelsRefresh')}
            title={t('settings.ai.modelsRefresh')}
            disabled={endpoint.trim() === '' || models.isFetching}
            onClick={() => void models.refetch()}
          >
            <RefreshIcon />
          </Button>
        </div>
        <input
          id="ai-model"
          type="text"
          autoComplete="off"
          value={model}
          placeholder={t('settings.ai.modelPlaceholder')}
          onChange={(event) => setModel(event.target.value)}
          // ponytail: <datalist> is the combo box: pick an offered model or type any.
          list="ai-models"
          className={inputClass}
        />
        <datalist id="ai-models">
          {models.data?.models.map((name) => (
            <option key={name} value={name} />
          ))}
        </datalist>
        <p className="text-[0.6875rem] text-faint" role="status">
          {models.isFetching
            ? t('settings.ai.modelsLoading')
            : models.isError
              ? t('settings.ai.modelsFailed', {
                  message:
                    models.error instanceof Error
                      ? models.error.message
                      : t('settings.ai.modelsFailedUnknown'),
                })
              : models.data
                ? t('settings.ai.modelsCount', {
                    count: models.data.models.length,
                  })
                : null}
        </p>
        <p className="text-[0.6875rem] text-faint">
          {t('settings.ai.modelHint')}
        </p>
      </div>

      <div className="flex justify-end">
        <Button
          type="button"
          disabled={!changed || endpoint.trim() === '' || save.isPending}
          onClick={() =>
            save.mutate({
              enabled,
              endpoint: endpoint.trim(),
              model: model.trim(),
            })
          }
        >
          {save.isPending ? t('settings.ai.saving') : t('settings.ai.save')}
        </Button>
      </div>

      {save.isError ? (
        <p className="text-[0.6875rem] text-critical">
          {save.error instanceof Error
            ? save.error.message
            : t('settings.ai.saveFailed')}
        </p>
      ) : null}
      {enabled && model.trim() === '' ? (
        <p className="text-[0.6875rem] text-critical">
          {t('settings.ai.modelRequired')}
        </p>
      ) : null}
    </section>
  )
}
