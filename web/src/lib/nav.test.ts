import { describe, expect, it } from 'vitest'

import {
  navBadge,
  navGroups,
  navItemFor,
  navItems,
  type NavItem,
} from './nav'

const projects = navItems.find((item) => item.label === 'Projects') as NavItem
const findings = navItems.find((item) => item.label === 'Findings') as NavItem

describe('navItems', () => {
  it('follows ADR-007: Findings before the ASSETS group, Connections last', () => {
    expect(navItems.map((item) => item.label)).toEqual([
      'Dashboard',
      'Findings',
      'Projects',
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
        label: group.label,
        items: group.items.map((item) => item.label),
      })),
    ).toEqual([
      { section: 'main', label: null, items: ['Dashboard', 'Findings'] },
      { section: 'assets', label: 'ASSETS', items: ['Projects'] },
      { section: 'settings', label: 'SETTINGS', items: ['Connections'] },
    ])
  })

  it('drops a group with no entries so no heading floats over nothing', () => {
    const mainOnly = navItems.filter((item) => item.section === undefined)
    expect(navGroups(mainOnly).map((group) => group.label)).toEqual([null])
  })
})

describe('navItemFor', () => {
  it('resolves the Projects route, including the Scans tab', () => {
    expect(navItemFor('/projects').label).toBe('Projects')
    expect(navItemFor('/projects/anything').label).toBe('Projects')
  })

  it('resolves the redirecting Scan History URL to Projects', () => {
    expect(navItemFor('/scan-history').label).toBe('Projects')
  })

  it('resolves the scan diff page to Projects (#17)', () => {
    expect(navItemFor('/scans/7/diff').label).toBe('Projects')
    expect(navItemFor('/scans/7/diff').to).toBe('/projects')
  })

  it('falls back to the dashboard for an unknown path', () => {
    expect(navItemFor('/nope').label).toBe('Dashboard')
  })
})

describe('navBadge', () => {
  it('shows the count in the pill and in the accessible name', () => {
    expect(navBadge(projects, { projects: 7 })).toEqual({
      name: 'Projects, 7',
      count: '7',
    })
    expect(navBadge(findings, { openFindings: 3 })).toEqual({
      name: 'Findings, 3',
      count: '3',
    })
  })

  it('hides the count while the query has no number', () => {
    expect(navBadge(projects, {})).toEqual({ name: 'Projects', count: null })
    expect(navBadge(findings, { openFindings: undefined })).toEqual({
      name: 'Findings',
      count: null,
    })
  })

  it('hides a zero count', () => {
    expect(navBadge(projects, { projects: 0 })).toEqual({
      name: 'Projects',
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
        name: item.label,
        count: null,
      })
    }
  })
})
