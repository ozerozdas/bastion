import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'

import { useDrawerFocus } from './drawer-focus'
import { HealthChip } from './health-chip'
import { CloseIcon, MenuIcon, MoonIcon, SettingsIcon, SunIcon } from './icons'
import { SettingsDialog } from './settings-dialog'
import { TrivyDBChip } from './trivy-db-chip'
import { UpdateNotice } from './update-notice'
import { assetsQuery, type Asset } from '../api/assets'
import type { FindingsSearch } from '../lib/urls'
import { dashboardQuery, openFindingTotal } from '../api/reports'
import { useT } from '../lib/i18n'
import {
  navBadge,
  navGroups,
  navItemFor,
  type NavCounts,
  type NavItem,
} from '../lib/nav'
import {
  resolveMode,
  setMode,
  storedMode,
  subscribeAppearance,
} from '../lib/theme'
import { cn } from '../lib/utils'

const pageActionsId = 'page-actions'
const sidebarId = 'app-sidebar'
const desktopQuery = '(min-width: 1024px)'

/**
 * subscribeDesktop reports the lg breakpoint to AppShell, which decides whether
 * the sidebar is the fixed column or the off-canvas drawer. One element is in
 * the DOM either way, so there is never a second navigation to land in.
 */
function subscribeDesktop(onChange: () => void): () => void {
  const media = window.matchMedia(desktopQuery)
  media.addEventListener('change', onChange)
  return () => media.removeEventListener('change', onChange)
}

function desktopSnapshot(): boolean {
  return window.matchMedia(desktopQuery).matches
}

function serverDesktopSnapshot(): boolean {
  return false
}

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
 * ProjectSwitcher sits after the Findings title: picking a project opens its
 * page and "All projects" returns to the fleet-wide list. It keeps the tab and
 * the list state that make sense on either page.
 */
function ProjectSwitcher({
  assets,
  current,
}: {
  assets: readonly Asset[]
  current: Asset | undefined
}) {
  const t = useT()
  const navigate = useNavigate()
  const search = useRouterState({ select: (state) => state.location.search }) as FindingsSearch
  const kept = {
    ...(search.tab === undefined ? {} : { tab: search.tab }),
    ...(search.q === undefined ? {} : { q: search.q }),
    ...(search.size === undefined ? {} : { size: search.size }),
    ...(search.sort === undefined ? {} : { sort: search.sort }),
    ...(search.order === undefined ? {} : { order: search.order }),
  }
  const repos = assets.filter((asset) => asset.kind !== 'image')
  const images = assets.filter((asset) => asset.kind === 'image')

  return (
    <select
      id="findings-project"
      aria-label={t('findings.filter.project')}
      value={current === undefined ? '' : String(current.id)}
      onChange={(event) => {
        const value = event.target.value
        void (value === ''
          ? navigate({ to: '/findings', search: { ...kept, tab: undefined } })
          : navigate({ to: '/findings/$assetId', params: { assetId: value }, search: kept }))
      }}
      className="h-8 max-w-[min(26rem,50vw)] min-w-0 truncate rounded-md border border-transparent bg-transparent pr-6 pl-1.5 text-[0.9375rem] font-semibold text-fg hover:border-border-subtle hover:bg-hover"
    >
      <option value="">{t('findings.filter.allProjects')}</option>
      {repos.length > 0 ? (
        <optgroup label={t('findings.filter.group.repositories')}>
          {repos.map((asset) => (
            <option key={asset.id} value={asset.id}>
              {asset.display_name}
            </option>
          ))}
        </optgroup>
      ) : null}
      {images.length > 0 ? (
        <optgroup label={t('findings.filter.group.images')}>
          {images.map((asset) => (
            <option key={asset.id} value={asset.id}>
              {asset.display_name}
            </option>
          ))}
        </optgroup>
      ) : null}
    </select>
  )
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
  const [drawerOpen, setDrawerOpen] = useState(false)
  const headingRef = useRef<HTMLHeadingElement>(null)
  // The route the drawer was opened from; a route change closes it and moves
  // focus into the new page instead of back to the menu button.
  const drawerPath = useRef(pathname)
  const previousPath = useRef(pathname)
  const isDesktop = useSyncExternalStore(
    subscribeDesktop,
    desktopSnapshot,
    serverDesktopSnapshot,
  )
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

  // A project's findings page names the project after its section.
  const pageAssetId = /^\/findings\/(\d+)/.exec(pathname)?.[1]
  const pageAsset =
    pageAssetId === undefined
      ? undefined
      : assets.data?.find((asset) => asset.id === Number(pageAssetId))
  const onFindings = pathname === '/findings' || pageAssetId !== undefined

  // A link inside the drawer navigates and the drawer must not stay over the
  // page it just opened; the same goes when the viewport grows past lg.
  useEffect(() => {
    if (previousPath.current === pathname) return
    previousPath.current = pathname
    if (!drawerOpen) return
    setDrawerOpen(false)
    headingRef.current?.focus()
  }, [pathname, drawerOpen])

  useEffect(() => {
    if (isDesktop) setDrawerOpen(false)
  }, [isDesktop])

  return (
    <div className="flex min-h-screen bg-bg text-fg">
      {isDesktop ? (
        <aside className="sticky top-0 flex h-screen w-[232px] shrink-0 flex-col gap-[18px] overflow-y-auto border-r border-border-subtle bg-sidebar px-3 py-4">
          <SidebarContent
            current={current}
            counts={counts}
            configOpen={configOpen}
            onOpenConfig={() => setConfigOpen(true)}
          />
        </aside>
      ) : null}

      {!isDesktop && drawerOpen ? (
        <SidebarDrawer
          id={sidebarId}
          label={t('app.nav.primary')}
          restoreFocus={drawerPath.current === pathname}
          onClose={() => setDrawerOpen(false)}
        >
          <SidebarContent
            current={current}
            counts={counts}
            configOpen={configOpen}
            onOpenConfig={() => {
              // The settings modal replaces the drawer; focus follows it.
              setDrawerOpen(false)
              setConfigOpen(true)
            }}
            onClose={() => setDrawerOpen(false)}
          />
        </SidebarDrawer>
      ) : null}

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex min-h-14 flex-wrap items-center gap-x-3 gap-y-1 border-b border-border-subtle px-4 py-2.5 sm:px-7">
          <button
            type="button"
            aria-label={t('app.nav.open')}
            aria-expanded={drawerOpen}
            aria-controls={drawerOpen && !isDesktop ? sidebarId : undefined}
            onClick={() => {
              drawerPath.current = pathname
              setDrawerOpen(true)
            }}
            className="-ml-1 flex size-8 shrink-0 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg lg:hidden"
          >
            <MenuIcon />
          </button>
          <h1
            ref={headingRef}
            tabIndex={-1}
            className="shrink-0 text-[0.9375rem] font-semibold focus:outline-none"
          >
            {pageAsset ? (
              <Link to="/findings" className="text-muted hover:text-fg hover:underline">
                {t(current.labelKey)}
              </Link>
            ) : (
              t(current.labelKey)
            )}
          </h1>
          {onFindings ? (
            <>
              <span aria-hidden="true" className="-mx-1.5 text-faint">›</span>
              <ProjectSwitcher assets={assets.data ?? []} current={pageAsset} />
            </>
          ) : null}
          {/* The dashboard hero and the project switcher say this themselves. */}
          {pathname === '/' || onFindings ? null : (
            <span className="min-w-0 text-faint">{t(current.subtitleKey)}</span>
          )}
          <div id={pageActionsId} className="ml-auto flex items-center gap-2" />
        </header>
        <div className="page-content flex flex-col gap-4 px-4 py-4 sm:px-7 sm:py-6">
          {children}
        </div>
      </main>

      {configOpen ? (
        <SettingsDialog onClose={() => setConfigOpen(false)} />
      ) : null}
    </div>
  )
}

/**
 * SidebarContent is everything the sidebar shows, so the fixed column and the
 * mobile drawer share one definition. onClose renders the drawer's close button.
 */
function SidebarContent({
  current,
  counts,
  configOpen,
  onOpenConfig,
  onClose,
}: {
  current: NavItem
  counts: NavCounts
  configOpen: boolean
  onOpenConfig: () => void
  onClose?: () => void
}) {
  const t = useT()
  return (
    <>
      <div className="flex items-center gap-2.5 px-2 py-1">
        {/* The app icon is the same file the favicon uses: one asset, served
            from the bundle, never fetched at runtime. */}
        <img src="/icon.svg" alt="" width={24} height={24} className="size-6" />
        <span className="text-sm font-semibold">Bastion</span>
        {onClose === undefined ? null : (
          <button
            type="button"
            aria-label={t('app.nav.close')}
            onClick={onClose}
            className="ml-auto flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg"
          >
            <CloseIcon />
          </button>
        )}
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
                onClick={onOpenConfig}
                className={cn(navItemClass, configOpen && navItemActiveClass)}
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
    </>
  )
}

/**
 * SidebarDrawer is the sidebar below lg: a panel over a scrim, with the shared
 * drawer focus behaviour, Escape and scrim to close, and the page scroll locked
 * while it is open.
 */
function SidebarDrawer({
  id,
  label,
  restoreFocus,
  onClose,
  children,
}: {
  id: string
  label: string
  restoreFocus: boolean
  onClose: () => void
  children: ReactNode
}) {
  const { panel, onKeyDown } = useDrawerFocus(onClose, { restoreFocus })

  useEffect(() => {
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [])

  return (
    <div className="fixed inset-0 z-40">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="absolute inset-0 overlay-scrim"
      />
      <div
        ref={panel}
        id={id}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="sidebar-drawer absolute inset-y-0 left-0 flex w-[232px] max-w-[calc(100vw-3rem)] flex-col gap-[18px] overflow-y-auto border-r border-border-subtle bg-sidebar px-3 py-4 shadow-xl focus:outline-none"
      >
        {children}
      </div>
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
