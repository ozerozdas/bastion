import { useQuery } from '@tanstack/react-query'

import { slaSettingsQuery } from '../api/reports'
import { useT } from '../lib/i18n'
import { SlaThresholdEditor } from './sla-threshold-editor'

/**
 * SlaSettings is Configuration's SLA section: the same threshold editor the
 * SLA report shows, so the setting can be changed without leaving settings.
 */
export function SlaSettings() {
  const t = useT()
  const { data } = useQuery(slaSettingsQuery)
  const title = t('settings.sla.title')

  return (
    <section
      aria-label={title}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex flex-col gap-1">
        <h2 className="text-[0.9375rem] font-semibold">{title}</h2>
        <p className="text-xs text-muted">{t('settings.sla.description')}</p>
      </div>
      {data === undefined ? null : <SlaThresholdEditor thresholds={data} />}
    </section>
  )
}
