/**
 * Per-install preferences (#150): the appearance choices, the language and the
 * dashboard dismissals used to live only in localStorage, which is scoped to
 * one origin, so serving bastion on another port lost them.
 *
 * They now also live on the server, keyed by the same localStorage key. The
 * browser copy stays the first-paint cache; installPreferences fetches the
 * server copy once and writes it over the cache, so the server wins. A setter
 * writes both, and the first run after the upgrade pushes the local value up
 * for every key the server does not have yet.
 */
import { api } from '../api/client'

/** The localStorage keys the UI synchronizes. */
export const themePreference = 'bastion-theme'
export const modePreference = 'bastion-mode'
export const fontFamilyPreference = 'bastion-font-family'
export const fontSizePreference = 'bastion-font-size'
export const languagePreference = 'bastion-language'
export const cliDonePreference = 'bastion:get-started:cli-done'
export const dismissedPreference = 'bastion:get-started:dismissed'

export const preferenceKeys = [
  themePreference,
  modePreference,
  fontFamilyPreference,
  fontSizePreference,
  languagePreference,
  cliDonePreference,
  dismissedPreference,
] as const

export type PreferenceKey = (typeof preferenceKeys)[number]

type Preferences = Record<string, string>

/**
 * ServerPreferences is the read shape: a key the server has no value for is
 * absent, which is how the upgrade migration tells "no copy" from a default.
 */
type ServerPreferences = Record<string, string | undefined>

const listeners = new Set<() => void>()

/**
 * changedBeforeSync holds keys the user set while the startup fetch was in
 * flight. Their local value is newer than the response, so syncPreferences
 * pushes it instead of overwriting it.
 */
const changedBeforeSync = new Set<PreferenceKey>()

let syncStarted = false

/** subscribePreferences notifies when a value changes locally or from the
 * server. Components read localStorage in their snapshot. */
export function subscribePreferences(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

function notify(): void {
  for (const listener of listeners) {
    listener()
  }
}

function readLocal(key: PreferenceKey): string | null {
  if (typeof localStorage === 'undefined') return null
  try {
    return localStorage.getItem(key)
  } catch {
    // Storage can be denied (private mode); the server copy still works.
    return null
  }
}

function writeLocal(key: PreferenceKey, value: string): void {
  if (typeof localStorage === 'undefined') return
  try {
    localStorage.setItem(key, value)
  } catch {
    // The choice still applies to this page even if it cannot be cached.
  }
}

/**
 * setPreference updates the cache, tells subscribers and sends the value to the
 * server. The request is fire-and-forget: being offline must not block a UI
 * interaction, and the cache keeps the choice either way.
 */
export function setPreference(key: PreferenceKey, value: string): void {
  writeLocal(key, value)
  changedBeforeSync.add(key)
  notify()
  void saveToServer({ [key]: value })
}

async function saveToServer(values: Preferences): Promise<void> {
  try {
    await api.put<Preferences>('/api/preferences', values)
  } catch (error) {
    console.warn('save preferences', error)
  }
}

/** installPreferences fetches the server copy once, after the first render. */
export function installPreferences(): void {
  if (syncStarted) return
  syncStarted = true
  void syncPreferences()
}

async function syncPreferences(): Promise<void> {
  let server: ServerPreferences
  try {
    server = await api.get<ServerPreferences>('/api/preferences')
  } catch (error) {
    // The localStorage cache is complete, so a failed read changes nothing.
    console.warn('load preferences', error)
    return
  }

  const push: Preferences = {}
  let applied = false

  for (const key of preferenceKeys) {
    const local = readLocal(key)
    if (changedBeforeSync.has(key)) {
      if (local !== null) push[key] = local
      continue
    }

    const remote = server[key]
    if (remote !== undefined) {
      if (remote !== local) {
        writeLocal(key, remote)
        applied = true
      }
      continue
    }

    // First run after the upgrade: the server has no copy, so migrate the
    // cached value up rather than lose it with this origin.
    if (local !== null) push[key] = local
  }

  if (applied) notify()
  if (Object.keys(push).length > 0) await saveToServer(push)
}
