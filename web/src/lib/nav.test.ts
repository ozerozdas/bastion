import { describe, expect, it } from 'vitest'

import { navBadge, navItems, type NavItem } from './nav'

const projects = navItems.find((item) => item.label === 'Projects') as NavItem
const reports = navItems.find(
  (item) => item.label === 'Security Reports',
) as NavItem

describe('navBadge', () => {
  it('shows the count in the pill and in the accessible name', () => {
    expect(navBadge(projects, { projects: 7 })).toEqual({
      name: 'Projects, 7',
      count: '7',
    })
    expect(navBadge(reports, { openFindings: 3 })).toEqual({
      name: 'Security Reports, 3',
      count: '3',
    })
  })

  it('hides the count while the query has no number', () => {
    expect(navBadge(projects, {})).toEqual({ name: 'Projects', count: null })
    expect(navBadge(reports, { openFindings: undefined })).toEqual({
      name: 'Security Reports',
      count: null,
    })
  })

  it('hides a zero count', () => {
    expect(navBadge(projects, { projects: 0 })).toEqual({
      name: 'Projects',
      count: null,
    })
    expect(navBadge(reports, { openFindings: 0 })).toEqual({
      name: 'Security Reports',
      count: null,
    })
  })

  it('ignores negative numbers', () => {
    expect(navBadge(projects, { projects: -1 }).count).toBeNull()
  })

  it('gives each entry only its own count', () => {
    const counts = { projects: 4, openFindings: 12 }
    expect(navBadge(projects, counts).count).toBe('4')
    expect(navBadge(reports, counts).count).toBe('12')
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
