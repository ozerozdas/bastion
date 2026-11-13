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
  parseFindingsSearch,
  parseProjectsTabSearch,
} from './lib/urls'
import { ConnectionsPage } from './pages/connections'
import { DashboardPage } from './pages/dashboard'
import { FindingsPage } from './pages/findings'
import { ProjectsPage } from './pages/projects'

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
  component: ConnectionsPage,
})

const projectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/projects',
  // ?tab=scans shows the scan list; without it the project list is shown.
  validateSearch: parseProjectsTabSearch,
  component: ProjectsPage,
})

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings',
  // ?asset=<id> narrows the list to one project and ?view=grouped groups it by
  // rule, so both survive reloads and links; without them every project's
  // findings are shown one per row.
  validateSearch: parseFindingsSearch,
  component: FindingsPage,
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
    throw redirect({ to: '/projects', search: { tab: 'scans' }, replace: true })
  },
})

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  connectionsRoute,
  projectsRoute,
  findingsRoute,
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
