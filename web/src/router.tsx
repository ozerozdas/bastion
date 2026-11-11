import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router'

import { AppShell } from './components/app-shell'
import { ConnectionsPage } from './pages/connections'
import { DashboardPage } from './pages/dashboard'
import { HistoryPage } from './pages/history'
import { ProjectsPage } from './pages/projects'
import { ReportsPage } from './pages/reports'

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
  component: ProjectsPage,
})

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/security-reports',
  component: ReportsPage,
})

const historyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scan-history',
  component: HistoryPage,
})

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  connectionsRoute,
  projectsRoute,
  reportsRoute,
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
