import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

import { mockApi } from './preview/mock-api'

// `make ui-preview`: the real UI with hot reload, answered by in-memory data.
export default defineConfig({
  plugins: [react(), tailwindcss(), mockApi()],
  server: { host: '127.0.0.1', port: 5199, strictPort: true },
})
