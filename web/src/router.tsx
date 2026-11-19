import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  redirect,
} from '@tanstack/react-router'

import { AppShell } from './components/app-shell'
import {
  parseAssetSearch,
  parseConfigurationsTab,
  parseConnectionsTab,
  parseContainersTab,
  parseFindingsSearch,
  parseProjectsTabSearch,
  parseScanDiffSearch,
} from './lib/urls'
import { AssetFindingsPage } from './pages/asset-findings'
import { ConfigurationsPage } from './pages/configurations'
import { ConnectionsPage } from './pages/connections'
import { ContainersPage } from './pages/containers'
import { DashboardPage } from './pages/dashboard'
import { FindingsPage } from './pages/findings'
import { ProjectsPage } from './pages/projects'
import { ReportPage, ReportsPage } from './pages/reports'
import { ScanDiffPage } from './pages/scan-diff'

function RootLayout() {
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}

const rootRoute = createRootRoute({ component: RootLayout })

// Code-based routes: five flat paths, so the generated route tree and its
// Vite plugin would be more machinery than this shell needs.
const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: DashboardPage,
})

const connectionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/connections',
  // ?tab=registry shows the registry placeholders; the bare path is the
  // repository sources (#107).
  validateSearch: parseConnectionsTab,
  component: ConnectionsPage,
})

const containersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/containers',
  // ?tab=aws-<id> or ?tab=orphaned picks a source; the bare path is the first
  // one available, which depends on the daemon and the connections (#120).
  validateSearch: parseContainersTab,
  component: ContainersPage,
})

const configurationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/configurations',
  // ?tab=<section> picks the settings panel; the bare path is Modules (#139).
  validateSearch: parseConfigurationsTab,
  component: ConfigurationsPage,
})

const repositoriesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/repositories',
  // ?tab=scans shows the scan list; without it the repository list is shown.
  validateSearch: parseProjectsTabSearch,
  component: ProjectsPage,
})

// Old links keep working; the query string (Scans tab, asset filter) carries
// over to the renamed route.
const legacyProjectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/projects',
  validateSearch: parseProjectsTabSearch,
  beforeLoad: ({ search }) => {
    throw redirect({ to: '/repositories', search, replace: true })
  },
})

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings',
  // Grouped is the default view and ?view=single opts out. ?asset=<id> is the
  // old form of the asset page, and the list's own filters still navigate here.
  validateSearch: parseFindingsSearch,
  beforeLoad: ({ search: { asset, ...search } }) => {
    if (!/^[1-9]\d*$/.test(String(asset))) return
    throw redirect({
      to: '/findings/$assetId',
      params: { assetId: String(asset) },
      search,
      replace: true,
    })
  },
  component: FindingsPage,
})

// One asset's findings with its scan status and rescan (#182).
const assetFindingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings/$assetId',
  validateSearch: parseFindingsSearch,
  beforeLoad: ({ params }) => {
    if (/^[1-9]\d*$/.test(params.assetId)) return
    throw redirect({ to: '/findings', replace: true })
  },
  component: AssetFindingsPage,
})

// What changed after a rescan: one scan against another of the same project
// (#17). ?against=<id> picks the baseline and defaults to the previous one.
const scanDiffRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/$scanId/diff',
  validateSearch: parseScanDiffSearch,
  component: ScanDiffPage,
})

// Reports (#190) is the card grid under Settings & More; ?asset=<id> scopes
// every report to one project.
const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  validateSearch: parseAssetSearch,
  component: ReportsPage,
})

// One report's page; the id picks the entry in the catalog.
const reportRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports/$reportId',
  validateSearch: parseAssetSearch,
  component: ReportPage,
})

// The old URLs keep working: /security-reports is the page's previous path.
// A bookmarked ?asset= id carries over to the same filtered findings list.
function redirectToFindings(search: { asset?: number }): never {
  throw redirect({ to: '/findings', search, replace: true })
}

const legacySecurityReportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/security-reports',
  validateSearch: parseAssetSearch,
  beforeLoad: ({ search }) => redirectToFindings(search),
})

const historyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scan-history',
  // Scan History is the Scans tab now (#88); the old URL opens that tab.
  beforeLoad: () => {
    throw redirect({ to: '/repositories', search: { tab: 'scans' }, replace: true })
  },
})

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  connectionsRoute,
  configurationsRoute,
  containersRoute,
  repositoriesRoute,
  legacyProjectsRoute,
  findingsRoute,
  assetFindingsRoute,
  scanDiffRoute,
  reportsRoute,
  reportRoute,
  legacySecurityReportsRoute,
  historyRoute,
])

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
