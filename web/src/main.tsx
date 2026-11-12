import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { applyTheme, storedTheme } from './lib/theme'
import { router } from './router'
import './styles.css'

// The CSP forbids inline scripts, so a pinned theme is applied here, before the first render.
applyTheme(storedTheme())

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The server is on loopback: failures are real, not network flakiness.
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

const container = document.getElementById('root')
if (!container) {
  throw new Error('missing #root element in index.html')
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
