import { describe, expect, it } from 'vitest'

import { t } from './i18n'
import { reportCatalog } from './report-catalog'

describe('reportCatalog', () => {
  it('lists the nine reports in the order the page shows them', () => {
    expect(reportCatalog.map((report) => report.id)).toEqual([
      'licenses-sbom',
      'trend',
      'cve-insights',
      'malware',
      'runtimes',
      'ci-history',
      'audit',
      'owasp-top10',
      'sla',
    ])
  })

  it('gives every report an English title and description', () => {
    for (const report of reportCatalog) {
      expect(t(report.titleKey), report.id).not.toBe(report.titleKey)
      expect(t(report.descriptionKey), report.id).not.toBe(
        report.descriptionKey,
      )
    }
  })

  it('gives every report an icon', () => {
    for (const report of reportCatalog) {
      expect(typeof report.icon, report.id).toBe('function')
    }
  })
})
