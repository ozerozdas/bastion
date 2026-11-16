import { describe, expect, it } from 'vitest'

import { t } from './i18n'
import {
  navBadge,
  navGroups,
  navItemFor,
  navItems,
  type NavItem,
} from './nav'

const projects = navItems.find(
  (item) => item.labelKey === 'nav.repositories',
) as NavItem
const containers = navItems.find(
  (item) => item.labelKey === 'nav.containers',
) as NavItem
const findings = navItems.find(
  (item) => item.labelKey === 'nav.findings',
) as NavItem

const label = (item: NavItem) => t(item.labelKey)

describe('navItems', () => {
  it('follows ADR-007: Findings before the ASSETS group, Connections last', () => {
    expect(navItems.map(label)).toEqual([
      'Dashboard',
      'Findings',
      'Repositories',
      'Containers',
      'Connections',
    ])
  })

  it('no longer lists Scan History as a sidebar entry', () => {
    expect(navItems.some((item) => item.to === '/scan-history')).toBe(false)
  })
})

describe('navGroups', () => {
  it('splits the entries into an unheaded top group, ASSETS and SETTINGS', () => {
    expect(
      navGroups().map((group) => ({
        section: group.section,
        label: group.labelKey === null ? null : t(group.labelKey),
        items: group.items.map(label),
      })),
    ).toEqual([
      { section: 'main', label: null, items: ['Dashboard', 'Findings'] },
      { section: 'assets', label: 'ASSETS', items: ['Repositories', 'Containers'] },
      { section: 'settings', label: 'SETTINGS', items: ['Connections'] },
    ])
  })

  it('drops a group with no entries so no heading floats over nothing', () => {
    const mainOnly = navItems.filter((item) => item.section === undefined)
    expect(
      navGroups(mainOnly).map((group) =>
        group.labelKey === null ? null : t(group.labelKey),
      ),
    ).toEqual([null])
  })
})

describe('navItemFor', () => {
  it('resolves the Repositories route, including the Scans tab', () => {
    expect(label(navItemFor('/repositories'))).toBe('Repositories')
    expect(label(navItemFor('/repositories/anything'))).toBe('Repositories')
    // The old /projects URL keeps the right header before its redirect.
    expect(label(navItemFor('/projects'))).toBe('Repositories')
  })

  it('resolves the Containers route', () => {
    expect(label(navItemFor('/containers'))).toBe('Containers')
  })

  it('resolves the redirecting Scan History URL to Repositories', () => {
    expect(label(navItemFor('/scan-history'))).toBe('Repositories')
  })

  it('resolves the scan diff page to Repositories (#17)', () => {
    expect(label(navItemFor('/scans/7/diff'))).toBe('Repositories')
    expect(navItemFor('/scans/7/diff').to).toBe('/repositories')
  })

  it('falls back to the dashboard for an unknown path', () => {
    expect(label(navItemFor('/nope'))).toBe('Dashboard')
  })
})

describe('navBadge', () => {
  it('shows the count in the pill and in the accessible name', () => {
    expect(navBadge(projects, { projects: 7 })).toEqual({
      name: 'Repositories, 7',
      count: '7',
    })
    expect(navBadge(findings, { openFindings: 3 })).toEqual({
      name: 'Findings, 3',
      count: '3',
    })
    expect(navBadge(containers, { containers: 2 })).toEqual({
      name: 'Containers, 2',
      count: '2',
    })
  })

  it('hides the count while the query has no number', () => {
    expect(navBadge(projects, {})).toEqual({ name: 'Repositories', count: null })
    expect(navBadge(findings, { openFindings: undefined })).toEqual({
      name: 'Findings',
      count: null,
    })
  })

  it('hides a zero count', () => {
    expect(navBadge(projects, { projects: 0 })).toEqual({
      name: 'Repositories',
      count: null,
    })
    expect(navBadge(findings, { openFindings: 0 })).toEqual({
      name: 'Findings',
      count: null,
    })
  })

  it('ignores negative numbers', () => {
    expect(navBadge(projects, { projects: -1 }).count).toBeNull()
  })

  it('gives each entry only its own count', () => {
    const counts = { projects: 4, openFindings: 12 }
    expect(navBadge(projects, counts).count).toBe('4')
    expect(navBadge(findings, counts).count).toBe('12')
  })

  it('never shows a count on entries that have none', () => {
    for (const item of navItems.filter((entry) => entry.count === undefined)) {
      expect(navBadge(item, { projects: 4, openFindings: 12 })).toEqual({
        name: label(item),
        count: null,
      })
    }
  })
})
