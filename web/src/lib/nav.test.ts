import { describe, expect, it } from 'vitest'

import { navBadge, navItems, type NavItem } from './nav'

const projects = navItems.find((item) => item.label === 'Projects') as NavItem
const findings = navItems.find((item) => item.label === 'Findings') as NavItem

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
