import { useSetAssetSchedule, type Asset } from '../api/assets'
import { useT } from '../lib/i18n'

const options = [
  { value: 'off', labelKey: 'schedule.off' },
  { value: 'daily', labelKey: 'schedule.daily' },
  { value: 'weekly', labelKey: 'schedule.weekly' },
] as const

/** ScanScheduleSelect sets how often one asset is scanned while bastion runs. */
export function ScanScheduleSelect({ asset }: { asset: Asset }) {
  const t = useT()
  const save = useSetAssetSchedule()

  return (
    <>
      <select
        aria-label={t('schedule.aria', { name: asset.display_name })}
        title={t('schedule.hint')}
        value={asset.scan_schedule}
        disabled={save.isPending}
        onChange={(event) =>
          save.mutate({
            id: asset.id,
            schedule: event.target.value as Asset['scan_schedule'],
          })
        }
        className="h-7 rounded-md border border-border-strong bg-surface px-1.5 text-xs text-fg"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {t(option.labelKey)}
          </option>
        ))}
      </select>
      {save.isError ? (
        <span role="alert" className="mt-1 block text-xs text-critical">
          {t('schedule.failed')}
        </span>
      ) : null}
    </>
  )
}
