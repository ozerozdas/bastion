import { useId, useState, type FormEvent } from 'react'

import {
  useSetSlaSettings,
  type SLAThresholds,
} from '../api/reports'
import { useT } from '../lib/i18n'
import {
  parseSlaThresholds,
  slaThresholdFields,
  slaThresholdMax,
  slaThresholdMin,
  thresholdValues,
  type SLAThresholdErrors,
  type SLAThresholdValues,
} from '../lib/report-sla'
import { cn } from '../lib/utils'
import { ErrorNote } from './error-note'
import { Button } from './ui/button'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg tabular-nums'

/**
 * SlaThresholdEditor edits the four severity thresholds (#190). It is shared
 * by the SLA report and Configuration's Policies tab, so both read and write
 * the same stored setting. Values are whole days in 1..3650, checked before
 * the request so a typo never reaches the API.
 */
export function SlaThresholdEditor({
  thresholds,
}: {
  thresholds: SLAThresholds
}) {
  const t = useT()
  const save = useSetSlaSettings()
  const id = useId()
  const [values, setValues] = useState<SLAThresholdValues>(() =>
    thresholdValues(thresholds),
  )
  const [errors, setErrors] = useState<SLAThresholdErrors>({})
  const [saved, setSaved] = useState(false)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const parsed = parseSlaThresholds(values)
    setErrors(parsed.errors)
    setSaved(false)
    if (parsed.thresholds === null) return
    save.mutate(parsed.thresholds, { onSuccess: () => setSaved(true) })
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {slaThresholdFields.map((field) => {
          const inputId = `${id}-${field}`
          const errorId = `${inputId}-error`
          const invalid = errors[field] === true
          return (
            <div key={field} className="flex flex-col gap-1">
              <label
                htmlFor={inputId}
                className="text-xs font-medium text-muted"
              >
                {t(`severity.${field}`)}
              </label>
              <input
                id={inputId}
                aria-label={t(`severity.${field}`)}
                type="number"
                inputMode="numeric"
                min={slaThresholdMin}
                max={slaThresholdMax}
                step={1}
                value={values[field]}
                aria-invalid={invalid ? true : undefined}
                aria-describedby={invalid ? errorId : undefined}
                onChange={(event) => {
                  setValues({ ...values, [field]: event.target.value })
                  setSaved(false)
                }}
                className={cn(inputClass, invalid && 'border-critical')}
              />
              {invalid ? (
                <p id={errorId} className="text-[0.6875rem] text-critical">
                  {t('settings.sla.invalid')}
                </p>
              ) : null}
            </div>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[0.6875rem] text-faint">
          {t('settings.sla.limit', {
            min: slaThresholdMin,
            max: slaThresholdMax,
          })}
        </p>
        <div className="flex items-center gap-2">
          {saved && save.isSuccess ? (
            <span role="status" className="text-[0.6875rem] text-ok">
              {t('settings.sla.saved')}
            </span>
          ) : null}
          <Button type="submit" size="sm" disabled={save.isPending}>
            {save.isPending ? t('settings.sla.saving') : t('settings.sla.save')}
          </Button>
        </div>
      </div>

      {save.isError ? (
        <ErrorNote error={save.error} fix={t('settings.sla.errorFix')} />
      ) : null}
    </form>
  )
}
