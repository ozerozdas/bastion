import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // The server answers with `Content-Security-Policy: default-src 'self'`
    // (PROJECT_SPEC.md §4.3), so the bundle may not contain inline script.
    // Vite's module-preload polyfill is injected inline; drop it.
    modulePreload: { polyfill: false },
  },
})
