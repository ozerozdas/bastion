/**
 * Interface language (#143): one JSON file per locale under src/locales.
 *
 * A locale file is flat, dotted keys and a `_meta.name` the picker shows:
 *
 *   { "_meta": { "name": "Türkçe" }, "nav.findings": "Bulgular" }
 *
 * Adding a language is dropping one file there: the glob below finds it, the
 * picker lists it and the browser's own language preference can select it.
 * English is the source of truth and the fallback for every missing key.
 */
import { useSyncExternalStore } from 'react'

import {
  languagePreference,
  setPreference,
  subscribePreferences,
} from './preferences'

/** Messages are flat, so a key is the whole path: "nav.findings". */
export type Messages = Record<string, string>

/** TranslationParams fill `{name}` placeholders; `count` also picks the plural. */
export type TranslationParams = Record<string, string | number>

type LocaleFile = Record<string, unknown>

type Locale = {
  /** Picker label, from the file's _meta.name. */
  name: string
  messages: Messages
}

const files = import.meta.glob<LocaleFile>('../locales/*.json', {
  eager: true,
  import: 'default',
})

const locales = new Map<string, Locale>()
for (const [path, data] of Object.entries(files)) {
  const code = path.slice(path.lastIndexOf('/') + 1, -'.json'.length)
  const messages: Messages = {}
  for (const [key, value] of Object.entries(data)) {
    if (key !== '_meta' && typeof value === 'string') {
      messages[key] = value
    }
  }
  locales.set(code, { name: metaName(data._meta, code), messages })
}

/** fallbackCode is English when it exists, otherwise whatever was discovered. */
const fallbackCode = locales.has('en')
  ? 'en'
  : ([...locales.keys()][0] ?? 'en')

function metaName(meta: unknown, code: string): string {
  if (typeof meta !== 'object' || meta === null) return code
  const name = (meta as { name?: unknown }).name
  return typeof name === 'string' ? name : code
}

/** LanguageOption is one entry in the Appearance tab's picker. */
export type LanguageOption = { value: string; label: string }

/** languageOptions is every discovered locale, English first. */
export const languageOptions: LanguageOption[] = [...locales.entries()]
  .map(([value, locale]) => ({ value, label: locale.name }))
  .sort((a, b) => {
    if (a.value === fallbackCode) return -1
    if (b.value === fallbackCode) return 1
    return a.value.localeCompare(b.value)
  })

const languageKey = languagePreference

/** readStoredLanguage returns the saved language when that file still exists. */
function readStoredLanguage(): string | null {
  if (typeof localStorage === 'undefined') return null
  try {
    const value = localStorage.getItem(languageKey)
    return value !== null && locales.has(value) ? value : null
  } catch {
    // Storage can be denied (private mode); the browser language still works.
    return null
  }
}

/**
 * detectLanguage prefers the stored choice, then the browser's languages
 * ("tr-TR" finds tr.json), then English.
 */
function detectLanguage(): string {
  const stored = readStoredLanguage()
  if (stored !== null) return stored

  const tags =
    typeof navigator === 'undefined'
      ? []
      : [...(navigator.languages ?? []), navigator.language]
  for (const tag of tags) {
    if (!tag) continue
    const lower = tag.toLowerCase()
    const base = lower.split('-')[0]
    if (locales.has(lower)) return lower
    if (locales.has(base)) return base
  }
  return fallbackCode
}

let current = detectLanguage()

const listeners = new Set<() => void>()

/** subscribeLanguage notifies when the picker changes the language. */
export function subscribeLanguage(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** language is the active locale code; it is also the store's snapshot. */
export function language(): string {
  return current
}

/** setLanguage stores the choice, sets <html lang> and re-renders the UI. */
export function setLanguage(code: string): void {
  if (!locales.has(code)) return
  // setPreference writes the cache and sends the choice to the server (#150).
  setPreference(languagePreference, code)
  applyLang(code)
  if (code === current) return
  current = code
  for (const listener of listeners) {
    listener()
  }
}

/** installI18n applies the detected language before the first render. */
export function installI18n(): void {
  current = detectLanguage()
  applyLang(current)
  // installPreferences (#150) overwrites the cache when the server copy
  // arrives; re-detect then, so the UI follows without a reload.
  subscribePreferences(refreshLanguage)
}

/**
 * refreshLanguage re-reads the cache after a server sync and re-renders when
 * the language changed.
 */
function refreshLanguage(): void {
  const next = detectLanguage()
  applyLang(next)
  if (next === current) return
  current = next
  for (const listener of listeners) {
    listener()
  }
}

/** applyLang keeps <html lang> in step, which screen readers and CSS use. */
function applyLang(code: string): void {
  if (typeof document !== 'undefined') {
    document.documentElement.lang = code
  }
}

/**
 * useT returns the translation function and re-renders the caller whenever the
 * language changes.
 */
export function useT(): typeof t {
  useSyncExternalStore(subscribeLanguage, language, language)
  return t
}

/** useLanguage returns the active locale code and re-renders on a change. */
export function useLanguage(): string {
  return useSyncExternalStore(subscribeLanguage, language, language)
}

/**
 * t translates one key in the active language, falling back to English and
 * then to the key itself. With a numeric `count` it tries the Intl plural
 * category first: "findings.count.one" and "findings.count.other".
 */
export function t(key: string, params?: TranslationParams): string {
  const template = lookup(key, params)
  return params === undefined ? template : interpolate(template, params)
}

function lookup(key: string, params: TranslationParams | undefined): string {
  const active = locales.get(current)?.messages
  const fallback = locales.get(fallbackCode)?.messages

  if (params !== undefined && typeof params.count === 'number') {
    const category = pluralCategory(current, params.count)
    const candidates =
      category === 'other'
        ? [`${key}.other`]
        : [`${key}.${category}`, `${key}.other`]
    for (const candidate of candidates) {
      const hit = active?.[candidate] ?? fallback?.[candidate]
      if (hit !== undefined) return hit
    }
  }

  return active?.[key] ?? fallback?.[key] ?? key
}

function pluralCategory(code: string, count: number): Intl.LDMLPluralRule {
  try {
    return new Intl.PluralRules(code).select(count)
  } catch {
    return 'other'
  }
}

function interpolate(template: string, params: TranslationParams): string {
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name]
    return value === undefined ? match : String(value)
  })
}

/** formatNumber formats with the active locale's separators and digits. */
export function formatNumber(
  value: number,
  options?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(current, options).format(value)
}

/** formatLocalDate formats a date with the active locale. */
export function formatLocalDate(
  value: Date,
  options: Intl.DateTimeFormatOptions,
): string {
  return new Intl.DateTimeFormat(current, options).format(value)
}
