import { useQuery } from '@tanstack/react-query'
import { Link, useRouterState } from '@tanstack/react-router'
import {
  useEffect,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'

import { HealthChip } from './health-chip'
import { MoonIcon, SettingsIcon, SunIcon } from './icons'
import { SettingsDialog } from './settings-dialog'
import { TrivyDBChip } from './trivy-db-chip'
import { UpdateNotice } from './update-notice'
import { assetsQuery } from '../api/assets'
import { dashboardQuery, openFindingTotal } from '../api/reports'
import { useT } from '../lib/i18n'
import { navBadge, navGroups, navItemFor, type NavCounts } from '../lib/nav'
import {
  resolveMode,
  setMode,
  storedMode,
  subscribeAppearance,
} from '../lib/theme'
import { cn } from '../lib/utils'

const pageActionsId = 'page-actions'

/** navItemClass is the look every sidebar entry shares, links and Configuration alike. */
const navItemClass =
  'flex h-[34px] items-center gap-2.5 rounded-md px-2.5 text-[0.8125rem] text-muted transition-colors hover:bg-hover hover:text-fg'
const navItemActiveClass =
  'bg-active text-fg shadow-[0_0_0_1px_var(--b-border-subtle)]'

/** PageActions renders its children at the right end of the page header. */
export function PageActions({ children }: { children: ReactNode }) {
  // ponytail: portal into the header slot; a context slot if pages need more.
  const [target, setTarget] = useState<HTMLElement | null>(null)
  useEffect(() => {
    setTarget(document.getElementById(pageActionsId))
  }, [])
  return target ? createPortal(children, target) : null
}

/**
 * AppShell is the concept's layout: a fixed 232px sidebar with the ADR-007
 * sections, a 56px header for the page title, and a scrolling page area.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const t = useT()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const current = navItemFor(pathname)
  const [configOpen, setConfigOpen] = useState(false)
  const assets = useQuery(assetsQuery)
  const dashboard = useQuery(dashboardQuery)
  const counts: NavCounts = {
    // Repositories are the non-image assets; images have their own entry.
    projects: assets.data?.filter((asset) => asset.kind !== 'image').length,
    containers: assets.data?.filter((asset) => asset.kind === 'image').length,
    openFindings: dashboard.data
      ? openFindingTotal(dashboard.data.totals_by_severity)
      : undefined,
  }

  return (
    <div className="flex min-h-screen bg-bg text-fg">
      <aside className="sticky top-0 flex h-screen w-[232px] shrink-0 flex-col gap-[18px] overflow-y-auto border-r border-border-subtle bg-sidebar px-3 py-4">
        <div className="flex items-center gap-2.5 px-2 py-1">
          {/* The app icon is the same file the favicon uses: one asset, served
              from the bundle, never fetched at runtime. */}
          <img src="/icon.svg" alt="" width={24} height={24} className="size-6" />
          <span className="text-sm font-semibold">Bastion</span>
        </div>

        <button
          type="button"
          disabled
          title={t('app.search.title')}
          className="flex h-8 items-center gap-2 rounded-md border border-border-strong bg-surface px-2.5 text-left text-xs text-faint disabled:cursor-not-allowed"
        >
          <SearchIcon />
          <span className="truncate">{t('app.search.placeholder')}</span>
          <span className="ml-auto rounded border border-border-strong px-1 font-mono text-[0.6875rem]">
            ⌘K
          </span>
        </button>

        <nav aria-label={t('app.nav.primary')} className="flex flex-col gap-3">
          {navGroups().map((group) => (
            <div
              key={group.section}
              role={group.labelKey === null ? undefined : 'group'}
              aria-labelledby={
                group.labelKey === null ? undefined : `nav-${group.section}`
              }
              className="flex flex-col gap-0.5"
            >
              {group.labelKey === null ? null : (
                <h2
                  id={`nav-${group.section}`}
                  className="px-2.5 pt-1 pb-1 text-[0.625rem] font-semibold tracking-[0.08em] text-faint uppercase"
                >
                  {t(group.labelKey)}
                </h2>
              )}
              {group.items.map((item) => {
                const active = item.to === current.to
                const Icon = item.icon
                const badge = navBadge(item, counts)
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    aria-label={badge.name}
                    aria-current={active ? 'page' : undefined}
                    className={cn(navItemClass, active && navItemActiveClass)}
                  >
                    <Icon />
                    {t(item.labelKey)}
                    {badge.count === null ? null : (
                      // The accessible name already carries the number, so the pill
                      // must not be read a second time.
                      <span
                        aria-hidden="true"
                        className="ml-auto min-w-[18px] rounded-full bg-surface px-1 text-center font-mono text-[0.6875rem] leading-[16px] tabular-nums"
                      >
                        {badge.count}
                      </span>
                    )}
                  </Link>
                )
              })}
              {group.section === 'settings' ? (
                <button
                  type="button"
                  aria-haspopup="dialog"
                  aria-expanded={configOpen}
                  onClick={() => setConfigOpen(true)}
                  className={cn(
                    navItemClass,
                    configOpen && navItemActiveClass,
                  )}
                >
                  <SettingsIcon />
                  {t('app.configuration')}
                </button>
              ) : null}
            </div>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-2">
          <UpdateNotice />
          <TrivyDBChip />
          <HealthChip action={<ThemeToggle />} />
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex min-h-14 flex-wrap items-center gap-3 border-b border-border-subtle px-7 py-2.5">
          <h1 className="text-[0.9375rem] font-semibold">
            {t(current.labelKey)}
          </h1>
          <span className="text-faint">{t(current.subtitleKey)}</span>
          <div id={pageActionsId} className="ml-auto flex items-center gap-2" />
        </header>
        <div className="flex flex-col gap-4 px-7 py-6">{children}</div>
      </main>

      {configOpen ? (
        <SettingsDialog onClose={() => setConfigOpen(false)} />
      ) : null}
    </div>
  )
}

/**
 * ThemeToggle flips light and dark inside the current theme family (#142). It
 * pins the mode, so the OS preference stops deciding until System is chosen
 * again in Configuration.
 */
function ThemeToggle() {
  const t = useT()
  const mode = useSyncExternalStore(subscribeAppearance, () =>
    resolveMode(storedMode()),
  )
  const next = mode === 'dark' ? 'light' : 'dark'
  const label = t('app.theme.switch', {
    mode: next === 'dark' ? t('app.theme.dark') : t('app.theme.light'),
  })

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={() => setMode(next)}
      className="flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg"
    >
      {mode === 'dark' ? <SunIcon /> : <MoonIcon />}
    </button>
  )
}

function SearchIcon() {
  return (
    <svg
      aria-hidden="true"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
    >
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </svg>
  )
}
