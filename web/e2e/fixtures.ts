import { spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { test as base, expect, type Page } from '@playwright/test'

export type Server = {
  /** Startup URL carrying the single-use token, as `bastion serve` prints it. */
  url: string
  /** Absolute directory added through the UI as a local-path project. */
  projectDir: string
}

const urlPattern = /http:\/\/127\.0\.0\.1:\d+\/\?t=[A-Za-z0-9_-]+/

const binary = resolve(dirname(fileURLToPath(import.meta.url)), '../../bin/bastion')

/**
 * startServer runs `bastion serve` on a free port with throwaway state. The URL
 * line goes to stderr, so both streams are scanned.
 */
export async function startServer(
  dataDir: string,
  cacheDir: string,
): Promise<{ child: ChildProcess; url: string }> {
  const child = spawn(
    binary,
    [
      'serve',
      '--no-browser',
      '--port',
      '0',
      '--data-dir',
      dataDir,
      '--cache-dir',
      cacheDir,
    ],
    {
      env: {
        ...process.env,
        // serve needs a local HMAC key; CI and this test are headless, so the
        // environment key replaces the OS keychain.
        BASTION_HMAC_KEY: randomBytes(32).toString('base64'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )

  const url = await new Promise<string>((resolveUrl, reject) => {
    let output = ''
    const timer = setTimeout(() => {
      reject(new Error(`bastion serve printed no URL in 20s:\n${output}`))
    }, 20_000)

    const scan = () => {
      const match = urlPattern.exec(output)
      if (match) {
        clearTimeout(timer)
        resolveUrl(match[0])
      }
    }
    child.stdout?.on('data', (chunk: Buffer) => {
      output += chunk.toString()
      scan()
    })
    child.stderr?.on('data', (chunk: Buffer) => {
      output += chunk.toString()
      scan()
    })
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.once('exit', (code, signal) => {
      clearTimeout(timer)
      reject(
        new Error(
          `bastion serve exited before printing a URL (code ${String(code)}, signal ${String(signal)}):\n${output}`,
        ),
      )
    })
  })

  return { child, url }
}

/** stopServer asks for a clean shutdown, then escalates if it hangs. */
export function stopServer(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve()
  }
  return new Promise((done) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      done()
    }, 5_000)
    child.once('exit', () => {
      clearTimeout(timer)
      done()
    })
    child.kill('SIGTERM')
  })
}

/**
 * test extends Playwright with a server fixture. It is test-scoped so every
 * test starts from an empty database and the tests cannot depend on each
 * other's order.
 */
export const test = base.extend<{ server: Server }>({
  server: async ({}, use) => {
    const root = await mkdtemp(join(tmpdir(), 'bastion-e2e-'))
    const dataDir = join(root, 'data')
    const cacheDir = join(root, 'cache')
    const projectDir = join(root, 'hello-project')
    await mkdir(dataDir)
    await mkdir(cacheDir)
    await mkdir(projectDir)
    await writeFile(
      join(projectDir, 'hello.txt'),
      'a local path the e2e test adds as a project\n',
    )

    const { child, url } = await startServer(dataDir, cacheDir)
    try {
      await use({ url, projectDir })
    } finally {
      await stopServer(child)
      await rm(root, { recursive: true, force: true })
    }
  },
})

/**
 * watch collects everything the browser complained about: console errors, page
 * errors and API responses the UI cannot render. The favicon request is
 * ignored because the bundle ships no favicon and its 404 says nothing about
 * the app.
 */
export function watch(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (message) => {
    if (message.type() !== 'error') {
      return
    }
    const where = message.location().url
    if (where.includes('favicon.ico') || message.text().includes('favicon.ico')) {
      return
    }
    problems.push(`console: ${message.text()} (${where})`)
  })
  page.on('pageerror', (error) => {
    problems.push(`page: ${error.message}`)
  })
  page.on('response', (response) => {
    if (response.url().includes('/api/') && response.status() >= 500) {
      problems.push(`api: ${String(response.status())} ${response.url()}`)
    }
  })
  return problems
}

export { expect }
