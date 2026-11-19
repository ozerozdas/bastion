import { useQuery } from '@tanstack/react-query'

import { securityNewsQuery, useSetSecurityNews } from '../api/security-news'
import { useT } from '../lib/i18n'
import { Badge } from './ui/badge'
import { Switch } from './ui/switch'

/**
 * SecurityNewsSettings is Configuration's opt-in card (#192): one switch for
 * the feature and one per preset source. Recommended sources start selected,
 * and the feature starts off, so nothing is fetched until it is turned on.
 */
export function SecurityNewsSettings() {
  const t = useT()
  const { data } = useQuery(securityNewsQuery)
  const setNews = useSetSecurityNews()

  if (!data) {
    return null
  }

  const enabled = data.enabled
  const selected = data.sources
    .filter((source) => source.enabled)
    .map((source) => source.id)

  const toggleSource = (id: string, on: boolean) => {
    setNews.mutate({
      enabled,
      sources: on ? [...selected, id] : selected.filter((value) => value !== id),
    })
  }

  return (
    <section
      aria-label={t('settings.news.title')}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-2">
        <h3 className="min-w-0 truncate text-[0.8125rem] font-semibold">
          {t('settings.news.title')}
        </h3>
        <Badge tone={enabled ? 'ok' : 'neutral'}>
          {enabled ? t('settings.badge.on') : t('settings.badge.off')}
        </Badge>
        <div className="-my-1 -mr-1 ml-auto">
          <Switch
            label={t('settings.news.title')}
            checked={enabled}
            disabled={setNews.isPending}
            onCheckedChange={(on) =>
              setNews.mutate({ enabled: on, sources: selected })
            }
          />
        </div>
      </div>

      <p className="text-xs leading-relaxed text-muted">
        {t('settings.news.body')}
      </p>

      <h4 className="text-xs font-medium text-faint">
        {t('settings.news.sources')}
      </h4>
      <ul className="flex flex-col divide-y divide-border-subtle border-t border-border-subtle">
        {data.sources.map((source) => (
          <li key={source.id} className="flex items-center gap-2 py-2">
            <span className="min-w-0 truncate text-[0.8125rem]">
              {source.name}
            </span>
            {source.recommended ? (
              <Badge tone="neutral">{t('settings.news.recommended')}</Badge>
            ) : null}
            {source.error === undefined ? null : (
              <span
                className="text-[0.6875rem] text-critical"
                title={source.error}
              >
                {t('settings.news.sourceFailed')}
              </span>
            )}
            <div className="-my-1 -mr-1 ml-auto">
              <Switch
                label={source.name}
                checked={source.enabled}
                disabled={!enabled || setNews.isPending}
                onCheckedChange={(on) => toggleSource(source.id, on)}
              />
            </div>
          </li>
        ))}
      </ul>

      <p className="text-[0.6875rem] text-faint">{t('settings.news.hint')}</p>
    </section>
  )
}
