import type { ComponentType } from 'react'

import {
  ConnectionsIcon,
  DashboardIcon,
  HistoryIcon,
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

export type NavItem = {
  /** Route path; "/" is the dashboard. */
  to: string
  label: string
  /** One line under the page title in the header. */
  subtitle: string
  icon: ComponentType
  /** Which sidebar count this entry shows, if any. */
  count?: keyof NavCounts
}

/** navItems is the five sections of PROJECT_SPEC.md §7, in the concept order. */
export const navItems: NavItem[] = [
  {
    to: '/',
    label: 'Dashboard',
    subtitle: 'Open findings across your projects',
    icon: DashboardIcon,
  },
  {
    to: '/connections',
    label: 'Connections',
    subtitle: 'GitHub, AWS and Docker sources',
    icon: ConnectionsIcon,
  },
  {
    to: '/projects',
    label: 'Projects',
    subtitle: 'Repositories and images you scan',
    icon: ProjectsIcon,
    count: 'projects',
  },
  {
    to: '/security-reports',
    label: 'Security Reports',
    subtitle: 'Findings per project, with fixes',
    icon: ReportsIcon,
    count: 'openFindings',
  },
  {
    to: '/scan-history',
    label: 'Scan History',
    subtitle: 'Every scan, comparable side by side',
    icon: HistoryIcon,
  },
]

/** navItemFor returns the nav entry for a pathname. */
export function navItemFor(pathname: string): NavItem {
  const match = navItems.find((item) =>
    item.to === '/' ? pathname === '/' : pathname.startsWith(item.to),
  )
  return match ?? navItems[0]
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
