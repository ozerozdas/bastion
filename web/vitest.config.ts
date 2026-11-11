import { defineConfig } from 'vitest/config'

// Unit tests cover the pure helpers in src/lib and the query-string builders in
// src/api. They run in node, without a DOM: anything that needs rendering is
// left to the Playwright smoke test.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
