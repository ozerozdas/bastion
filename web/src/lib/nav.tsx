import type { ComponentType } from 'react'

import {
  ConnectionsIcon,
  DashboardIcon,
  HistoryIcon,
  ProjectsIcon,
  ReportsIcon,
} from '../components/icons'

export type NavItem = {
  /** Route path; "/" is the dashboard. */
  to: string
  label: string
  /** One line under the page title in the header. */
  subtitle: string
  icon: ComponentType
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
  },
  {
    to: '/security-reports',
    label: 'Security Reports',
    subtitle: 'Findings per project, with fixes',
    icon: ReportsIcon,
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
