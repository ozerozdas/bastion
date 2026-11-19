import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'

import { securityNewsQuery } from '../api/security-news'
import { EmptyState } from '../components/empty-state'
import { ErrorNote } from '../components/error-note'
import { BandHeader, BandSummary } from '../components/page-band'
import { buttonVariants } from '../components/ui/button'
import { useT } from '../lib/i18n'
import { relativeTime } from '../lib/time'

/** publishedLabel renders a feed date, hiding the zero value an undated entry has. */
function publishedLabel(value: string): string | null {
  return value.startsWith('0001-') ? null : relativeTime(value)
}

/**
 * SecurityNewsPage is the full feed (#192): every item of the enabled sources,
 * newest first. It is reachable from the sidebar only while the feature is on,
 * but a bookmarked URL still explains the off state.
 */
export function SecurityNewsPage() {
  const t = useT()
  const query = useQuery(securityNewsQuery)

  const band = (
    <BandHeader>
      <BandSummary
        title={t('nav.securityNews')}
        subtitle={t('nav.securityNews.subtitle')}
      />
    </BandHeader>
  )

  if (query.status === 'pending') {
    return (
      <>
        {band}
        <section className="rounded-card border border-border-subtle bg-surface p-4">
          <p className="text-muted">{t('securityNews.loading')}</p>
        </section>
      </>
    )
  }

  if (query.status === 'error') {
    return (
      <>
        {band}
        <section className="flex flex-col gap-1 rounded-card border border-border-subtle bg-surface p-4">
          <h2 className="text-[0.8125rem] font-semibold">
            {t('securityNews.failed')}
          </h2>
          <ErrorNote error={query.error} />
        </section>
      </>
    )
  }

  const data = query.data
  if (!data.enabled) {
    return (
      <>
        {band}
        <EmptyState
          title={t('securityNews.disabled.title')}
          body={t('securityNews.disabled.body')}
        >
          <Link to="/configurations" className={buttonVariants()}>
            {t('securityNews.disabled.action')}
          </Link>
        </EmptyState>
      </>
    )
  }

  if (data.items.length === 0) {
    return (
      <>
        {band}
        <EmptyState
          title={t('securityNews.empty.title')}
          body={t('securityNews.empty.body')}
        />
      </>
    )
  }

  return (
    <>
      {band}
      <ul aria-label={t('securityNews.aria')} className="flex flex-col gap-3">
        {data.items.map((item) => {
          const published = publishedLabel(item.published)
          return (
            <li key={`${item.source_id}:${item.link}`}>
              <article className="flex flex-col gap-1.5 rounded-card border border-border-subtle bg-surface p-4">
                <p className="text-xs text-faint">
                  {item.source}
                  {published === null ? '' : ` · ${published}`}
                </p>
                <h2 className="text-[0.875rem] font-semibold">
                  <a
                    href={item.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:underline"
                  >
                    {item.title}
                  </a>
                </h2>
                {item.summary === '' ? null : (
                  <p className="text-xs leading-relaxed text-muted">
                    {item.summary}
                  </p>
                )}
              </article>
            </li>
          )
        })}
      </ul>
    </>
  )
}
