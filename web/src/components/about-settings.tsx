import { useT } from '../lib/i18n'

const repo = 'https://github.com/ozerozdas/bastion'
const site = 'https://mehmetozer.dev'
const supportClass =
  'inline-flex h-8 items-center gap-1.5 rounded-md border border-border-strong px-3 text-xs font-medium text-fg transition-colors hover:bg-hover'
const linkClass = 'text-fg underline underline-offset-2 hover:text-accent'

/** AboutSettings is Configuration's About tab: what Bastion is and who built it. */
export function AboutSettings() {
  const t = useT()
  return (
    <section
      aria-label={t('settings.tabs.about')}
      className="flex w-full max-w-2xl flex-col gap-4 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-3">
        <img src="/icon.svg" alt="" width={32} height={32} className="size-8" />
        <h2 className="text-[0.9375rem] font-semibold">Bastion</h2>
      </div>
      <p className="text-[0.8125rem] text-muted">
        {t('settings.about.summary')}
      </p>

      <div className="flex flex-col gap-0.5 border-t border-border-subtle pt-3">
        <span className="text-xs text-faint">{t('settings.about.author')}</span>
        <a
          href={site}
          target="_blank"
          rel="noreferrer"
          className="text-base font-semibold text-fg hover:text-accent"
        >
          Mehmet Özer Özdaş
        </a>
        <a
          href={site}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-muted hover:text-accent"
        >
          mehmetozer.dev
        </a>
      </div>

      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 border-t border-border-subtle pt-3 text-xs">
        <dt className="text-faint">{t('settings.about.repo')}</dt>
        <dd>
          <a href={repo} target="_blank" rel="noreferrer" className={linkClass}>
            github.com/ozerozdas/bastion
          </a>
        </dd>
        <dt className="text-faint">{t('settings.about.docs')}</dt>
        <dd>
          <a
            href={`${repo}/wiki`}
            target="_blank"
            rel="noreferrer"
            className={linkClass}
          >
            Wiki
          </a>
        </dd>
        <dt className="text-faint">{t('settings.about.license')}</dt>
        <dd className="text-fg">Apache-2.0</dd>
      </dl>

      <div className="flex flex-col gap-2 border-t border-border-subtle pt-3">
        <p className="text-xs text-muted">{t('settings.about.support')}</p>
        <div className="flex flex-wrap gap-1.5">
          <a
            href="https://buymeacoffee.com/ozerozdas"
            target="_blank"
            rel="noreferrer"
            className={supportClass}
          >
            ☕ Buy me a coffee
          </a>
          <a
            href="https://github.com/sponsors/ozerozdas"
            target="_blank"
            rel="noreferrer"
            className={supportClass}
          >
            ♥ GitHub Sponsors
          </a>
        </div>
      </div>
    </section>
  )
}
