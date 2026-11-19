import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'

import { securityNewsQuery, useSetSecurityNews } from '../api/security-news'
import { useT } from '../lib/i18n'
import { relativeTime } from '../lib/time'
import { Button } from './ui/button'

/** publishedLabel renders a feed date, hiding the zero value an undated entry has. */
function publishedLabel(value: string): string | null {
  return value.startsWith('0001-') ? null : relativeTime(value)
}

/**
 * SecurityNewsSection is the dashboard's last block (#192): a horizontally
 * scrollable row of cards. It renders nothing while the feature is off, so the
 * dashboard is unchanged until the user opts in.
 */
export function SecurityNewsSection() {
  const t = useT()
  const { data } = useQuery(securityNewsQuery)
  if (data?.enabled !== true || data.items.length === 0) {
    return null
  }

  return (
    <section
      aria-labelledby="security-news-heading"
      className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface px-4 py-3.5"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="security-news-heading" className="text-[0.8125rem] font-semibold">
          {t('dashboard.news.title')}
        </h2>
        <Link
          to="/security-news"
          className="ml-auto text-xs text-muted underline underline-offset-2 hover:text-fg"
        >
          {t('dashboard.news.all')}
        </Link>
      </div>
      <ul className="flex snap-x gap-3 overflow-x-auto pb-1">
        {data.items.map((item) => {
          const published = publishedLabel(item.published)
          return (
            <li
              key={`${item.source_id}:${item.link}`}
              className="flex min-w-[16rem] shrink-0 snap-start flex-col gap-1 rounded-md border border-border-subtle p-3 sm:max-w-[18rem]"
            >
              <p className="truncate text-[0.6875rem] text-faint">
                {item.source}
                {published === null ? '' : ` · ${published}`}
              </p>
              <a
                href={item.link}
                target="_blank"
                rel="noopener noreferrer"
                className="line-clamp-2 text-[0.8125rem] font-medium hover:underline"
              >
                {item.title}
              </a>
              {item.summary === '' ? null : (
                <p className="line-clamp-2 text-xs leading-relaxed text-muted">
                  {item.summary}
                </p>
              )}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

/**
 * SecurityNewsRecommendation is the optional Quick Setup suggestion: while the
 * feature is off, the Get Started card offers to turn it on with the
 * recommended sources.
 */
export function SecurityNewsRecommendation() {
  const t = useT()
  const { data } = useQuery(securityNewsQuery)
  const setNews = useSetSecurityNews()
  if (data === undefined || data.enabled) {
    return null
  }
  const recommended = data.sources
    .filter((source) => source.recommended)
    .map((source) => source.id)

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-border-subtle pt-2.5 text-xs text-muted">
      <span>{t('dashboard.getStarted.news')}</span>
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={setNews.isPending}
        onClick={() => setNews.mutate({ enabled: true, sources: recommended })}
      >
        {t('dashboard.getStarted.newsAction')}
      </Button>
    </div>
  )
}
