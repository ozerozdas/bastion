import { useQuery } from '@tanstack/react-query'
import { Link, useRouterState } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'

import { HealthChip } from './health-chip'
import { MoonIcon, SunIcon } from './icons'
import { TrivyDBChip } from './trivy-db-chip'
import { UpdateNotice } from './update-notice'
import { assetsQuery } from '../api/assets'
import { dashboardQuery, openFindingTotal } from '../api/reports'
import { navBadge, navGroups, navItemFor, type NavCounts } from '../lib/nav'
import { applyTheme, currentTheme, type Theme } from '../lib/theme'
import { cn } from '../lib/utils'

/**
 * AppShell is the concept's layout: a fixed 232px sidebar with the ADR-007
 * sections, a 56px header for the page title, and a scrolling page area.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const current = navItemFor(pathname)
  const assets = useQuery(assetsQuery)
  const dashboard = useQuery(dashboardQuery)
  const counts: NavCounts = {
    // The API lists non-archived assets only, so the length is the count.
    projects: assets.data?.length,
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
          title="Search arrives with the findings table"
          className="flex h-8 items-center gap-2 rounded-md border border-border-strong bg-surface px-2.5 text-left text-xs text-faint disabled:cursor-not-allowed"
        >
          <SearchIcon />
          <span className="truncate">Search findings, CVEs…</span>
          <span className="ml-auto rounded border border-border-strong px-1 font-mono text-[11px]">
            ⌘K
          </span>
        </button>

        <nav aria-label="Primary" className="flex flex-col gap-3">
          {navGroups().map((group) => (
            <div
              key={group.section}
              role={group.label === null ? undefined : 'group'}
              aria-labelledby={
                group.label === null ? undefined : `nav-${group.section}`
              }
              className="flex flex-col gap-0.5"
            >
              {group.label === null ? null : (
                <h2
                  id={`nav-${group.section}`}
                  className="px-2.5 pt-1 pb-1 text-[10px] font-semibold tracking-[0.08em] text-faint uppercase"
                >
                  {group.label}
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
                    className={cn(
                      'flex h-[34px] items-center gap-2.5 rounded-md px-2.5 text-[13px] text-muted transition-colors hover:bg-hover hover:text-fg',
                      active &&
                        'bg-active text-fg shadow-[0_0_0_1px_var(--b-border-subtle)]',
                    )}
                  >
                    <Icon />
                    {item.label}
                    {badge.count === null ? null : (
                      // The accessible name already carries the number, so the pill
                      // must not be read a second time.
                      <span
                        aria-hidden="true"
                        className="ml-auto min-w-[18px] rounded-full bg-surface px-1 text-center font-mono text-[11px] leading-[16px] tabular-nums"
                      >
                        {badge.count}
                      </span>
                    )}
                  </Link>
                )
              })}
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
          <h1 className="text-[15px] font-semibold">{current.label}</h1>
          <span className="text-faint">{current.subtitle}</span>
        </header>
        <div className="flex flex-col gap-4 px-7 py-6">{children}</div>
      </main>
    </div>
  )
}

/** ThemeToggle flips between light and dark and remembers the choice. */
function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(currentTheme)
  const next: Theme = theme === 'dark' ? 'light' : 'dark'
  const label = `Switch to ${next} theme`

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={() => {
        applyTheme(next)
        setTheme(next)
      }}
      className="flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg"
    >
      {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
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
