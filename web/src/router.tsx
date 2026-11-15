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
  parseConnectionsTab,
  parseFindingsSearch,
  parseProjectsTabSearch,
  parseScanDiffSearch,
} from './lib/urls'
import { ConnectionsPage } from './pages/connections'
import { ContainersPage } from './pages/containers'
import { DashboardPage } from './pages/dashboard'
import { FindingsPage } from './pages/findings'
import { ProjectsPage } from './pages/projects'
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
  component: ContainersPage,
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
  // Grouped is the default view; ?view=single opts out, and ?asset=<id>
  // narrows the list to one project, which is always single. Both survive
  // reloads and links.
  validateSearch: parseFindingsSearch,
  component: FindingsPage,
})

// What changed after a rescan: one scan against another of the same project
// (#17). ?against=<id> picks the baseline and defaults to the previous one.
const scanDiffRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/$scanId/diff',
  validateSearch: parseScanDiffSearch,
  component: ScanDiffPage,
})

// The old URLs keep working: /security-reports is the page's previous path and
// /reports is the short form named in #87. A bookmarked ?asset= id carries over
// to the same filtered list.
function redirectToFindings(search: { asset?: number }): never {
  throw redirect({ to: '/findings', search, replace: true })
}

const legacyReportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  validateSearch: parseAssetSearch,
  beforeLoad: ({ search }) => redirectToFindings(search),
})

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
  containersRoute,
  repositoriesRoute,
  legacyProjectsRoute,
  findingsRoute,
  scanDiffRoute,
  legacyReportsRoute,
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
