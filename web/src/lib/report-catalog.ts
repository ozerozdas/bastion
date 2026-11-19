import type { ComponentType, SVGProps } from 'react'

import {
  BranchIcon,
  CheckIcon,
  ClockIcon,
  ContainersIcon,
  DashboardIcon,
  FilterIcon,
  InfoIcon,
  ProjectsIcon,
  ReportsIcon,
} from '../components/icons'

/** ReportId names one report: its card, its page and its URL segment. */
export type ReportId =
  | 'licenses-sbom'
  | 'trend'
  | 'cve-insights'
  | 'malware'
  | 'runtimes'
  | 'ci-history'
  | 'audit'
  | 'owasp-top10'
  | 'sla'

/** ReportDefinition is one card on /reports and one /reports/<id> page. */
export type ReportDefinition = {
  id: ReportId
  /** Translation key of the card title and the report page title. */
  titleKey: string
  /** Translation key of the card's one-line description. */
  descriptionKey: string
  icon: ComponentType<SVGProps<SVGSVGElement>>
}

/**
 * reportCatalog is the reports the page lists, in the order it shows them. The
 * panels behind them arrive in later milestones; the shell is the same.
 */
export const reportCatalog: readonly ReportDefinition[] = [
  {
    id: 'licenses-sbom',
    titleKey: 'reports.licenses-sbom.title',
    descriptionKey: 'reports.licenses-sbom.description',
    icon: ProjectsIcon,
  },
  {
    id: 'trend',
    titleKey: 'reports.trend.title',
    descriptionKey: 'reports.trend.description',
    icon: DashboardIcon,
  },
  {
    id: 'cve-insights',
    titleKey: 'reports.cve-insights.title',
    descriptionKey: 'reports.cve-insights.description',
    icon: InfoIcon,
  },
  {
    id: 'malware',
    titleKey: 'reports.malware.title',
    descriptionKey: 'reports.malware.description',
    icon: ReportsIcon,
  },
  {
    id: 'runtimes',
    titleKey: 'reports.runtimes.title',
    descriptionKey: 'reports.runtimes.description',
    icon: ContainersIcon,
  },
  {
    id: 'ci-history',
    titleKey: 'reports.ci-history.title',
    descriptionKey: 'reports.ci-history.description',
    icon: BranchIcon,
  },
  {
    id: 'audit',
    titleKey: 'reports.audit.title',
    descriptionKey: 'reports.audit.description',
    icon: CheckIcon,
  },
  {
    id: 'owasp-top10',
    titleKey: 'reports.owasp-top10.title',
    descriptionKey: 'reports.owasp-top10.description',
    icon: FilterIcon,
  },
  {
    id: 'sla',
    titleKey: 'reports.sla.title',
    descriptionKey: 'reports.sla.description',
    icon: ClockIcon,
  },
]
