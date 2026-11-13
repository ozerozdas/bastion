import type { ComponentType } from 'react'

import {
  ConnectionsIcon,
  DashboardIcon,
  ProjectsIcon,
  ReportsIcon,
} from '../components/icons'

/** NavCounts are the numbers the sidebar can show; a missing key is "not known yet". */
export type NavCounts = {
  /** Non-archived projects from assetsQuery. */
  projects?: number
  /** Open findings from dashboardQuery. */
  openFindings?: number
}

/** NavSection is where an entry sits in the sidebar; the top group has no heading. */
export type NavSection = 'main' | 'assets' | 'settings'

export type NavItem = {
  /** Route path; "/" is the dashboard. */
  to: string
  label: string
  /** One line under the page title in the header. */
  subtitle: string
  icon: ComponentType
  /** Which sidebar count this entry shows, if any. */
  count?: keyof NavCounts
  /** Heading group; omitted means the unheaded top group (ADR-007). */
  section?: Exclude<NavSection, 'main'>
}

/** navItems follows ADR-007: Findings is a main view, Projects owns the scans. */
export const navItems: NavItem[] = [
  {
    to: '/',
    label: 'Dashboard',
    subtitle: 'Open findings across your projects',
    icon: DashboardIcon,
  },
  {
    to: '/findings',
    label: 'Findings',
    subtitle: 'Across every project, with fixes',
    icon: ReportsIcon,
    count: 'openFindings',
  },
  {
    to: '/projects',
    label: 'Projects',
    subtitle: 'Repositories and images you scan',
    icon: ProjectsIcon,
    count: 'projects',
    section: 'assets',
  },
  {
    to: '/connections',
    label: 'Connections',
    subtitle: 'GitHub, AWS and Docker sources',
    icon: ConnectionsIcon,
    section: 'settings',
  },
]

/** NavGroup is one heading and the entries under it. */
export type NavGroup = {
  section: NavSection
  /** Heading above the group; null for the top entries. */
  label: string | null
  items: NavItem[]
}

/** navGroups splits navItems into the ADR-007 sections, in their order. */
export function navGroups(items: NavItem[] = navItems): NavGroup[] {
  const groups: NavGroup[] = [
    { section: 'main', label: null, items: [] },
    { section: 'assets', label: 'ASSETS', items: [] },
    { section: 'settings', label: 'SETTINGS', items: [] },
  ]
  for (const item of items) {
    const group = groups.find((entry) => entry.section === (item.section ?? 'main'))
    group?.items.push(item)
  }
  // A section without entries would render a heading over nothing.
  return groups.filter((group) => group.items.length > 0)
}

/** legacyPathnames keeps the header sensible for URLs that redirect (#88). */
const legacyPathnames: Record<string, string> = {
  '/scan-history': '/projects',
}

/** sectionPathnames keeps a page under the nav entry that owns it (#17). */
const sectionPathnames: { prefix: string; to: string }[] = [
  // The scan diff page is the Scans tab's detail view.
  { prefix: '/scans/', to: '/projects' },
]

/** navItemFor returns the nav entry for a pathname. */
export function navItemFor(pathname: string): NavItem {
  const path = legacyPathnames[pathname] ?? pathname
  const match = navItems.find((item) =>
    item.to === '/' ? path === '/' : path.startsWith(item.to),
  )
  if (match !== undefined) return match
  const section = sectionPathnames.find((entry) => path.startsWith(entry.prefix))
  return navItems.find((item) => item.to === section?.to) ?? navItems[0]
}

/** NavBadge is one entry's count as the sidebar shows it. */
export type NavBadge = {
  /** The link's accessible name: the label, plus the count when one is shown. */
  name: string
  /** Pill text, or null when nothing should be rendered. */
  count: string | null
}

/**
 * navBadge decides whether an entry shows a count. Undefined means the query is
 * still loading or failed, and zero means there is nothing to report: both hide
 * the pill and leave the label alone.
 */
export function navBadge(item: NavItem, counts: NavCounts): NavBadge {
  const count = item.count === undefined ? undefined : counts[item.count]
  if (count === undefined || count <= 0) {
    return { name: item.label, count: null }
  }
  const text = String(count)
  return { name: `${item.label}, ${text}`, count: text }
}
