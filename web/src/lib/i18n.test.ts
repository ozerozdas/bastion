import { describe, expect, it } from 'vitest'

/**
 * The locale files are the source of truth for keys: a key the UI asks for must
 * exist in en.json, and a translation must not drift from it. Vite globs read
 * the files raw, so the test needs no Node APIs.
 */
const localeSources = import.meta.glob<string>('../locales/*.json', {
  query: '?raw',
  import: 'default',
  eager: true,
})
const uiSources = import.meta.glob<string>(
  ['../**/*.{ts,tsx}', '!../**/*.test.{ts,tsx}', '!../locales/**'],
  { query: '?raw', import: 'default', eager: true },
)

type LocaleFile = Record<string, unknown>

function localeFile(code: string): LocaleFile {
  return JSON.parse(localeSources[`../locales/${code}.json`] ?? '{}') as LocaleFile
}

/** readLocale returns the flat messages, without the _meta block. */
function readLocale(code: string): Record<string, string> {
  const data = localeFile(code)
  const messages: Record<string, string> = {}
  for (const [key, value] of Object.entries(data)) {
    if (key !== '_meta' && typeof value === 'string') {
      messages[key] = value
    }
  }
  return messages
}

/** metaName reads the picker label the file declares. */
function metaName(code: string): string | undefined {
  const meta = localeFile(code)._meta
  if (typeof meta !== 'object' || meta === null) return undefined
  const name = (meta as { name?: unknown }).name
  return typeof name === 'string' ? name : undefined
}

/** localeCodes is every file in src/locales, English included. */
function localeCodes(): string[] {
  return Object.keys(localeSources)
    .map((path) => path.replace('../locales/', '').replace(/\.json$/, ''))
    .sort()
}

/** placeholders is the set of {name} fields a message interpolates. */
function placeholders(message: string): string[] {
  return [...message.matchAll(/\{(\w+)\}/g)]
    .map((match) => match[1] ?? '')
    .sort()
}

/**
 * perLocaleParams lists the keys where a locale deliberately interpolates a
 * different parameter of the same call: percentileLabel() passes both `ordinal`
 * and `percent`, and English writes "94th pct" where Turkish writes "%94".
 * Every other key must use exactly the placeholders English uses.
 */
const perLocaleParams: Record<string, Record<string, string[]>> = {
  'epss.percentile': Object.fromEntries(
    ['tr', 'es', 'pt', 'ja', 'zh'].map((code) => [code, ['percent']]),
  ),
}

const codes = localeCodes()
const messages = new Map(codes.map((code) => [code, readLocale(code)]))
const en = messages.get('en') ?? {}
const enKeys = Object.keys(en)

describe('locale files', () => {
  it('ship English as the source of truth', () => {
    expect(codes).toContain('en')
    expect(metaName('en')).toBeTruthy()
  })

  it('declare a picker name in every file', () => {
    for (const code of codes) {
      expect(metaName(code), `${code}.json _meta.name`).toBeTruthy()
    }
  })

  it('use exactly the keys English has, in every language', () => {
    for (const code of codes) {
      if (code === 'en') continue
      const keys = Object.keys(messages.get(code) ?? {})
      expect(
        enKeys.filter((key) => !keys.includes(key)),
        `${code}.json is missing keys`,
      ).toEqual([])
      expect(
        keys.filter((key) => !enKeys.includes(key)),
        `${code}.json has keys English does not`,
      ).toEqual([])
    }
  })

  it('interpolate the same placeholders as English', () => {
    for (const code of codes) {
      if (code === 'en') continue
      const locale = messages.get(code) ?? {}
      for (const key of enKeys) {
        const expected =
          perLocaleParams[key]?.[code] ?? placeholders(en[key] ?? '')
        expect(
          placeholders(locale[key] ?? ''),
          `${code}.json ${key} placeholders`,
        ).toEqual(expected)
      }
    }
  })
})

describe('t() keys used by the UI', () => {
  /**
   * resolves accepts a plural call: t('key', { count }) reads key.one and
   * key.other, so the literal itself is not a key of its own.
   */
  function resolves(key: string): boolean {
    return key in en || `${key}.one` in en || `${key}.other` in en
  }

  it('all exist in en.json', () => {
    const missing: string[] = []
    const files = Object.entries(uiSources)
    expect(files.length).toBeGreaterThan(20)
    for (const [file, source] of files) {
      for (const match of source.matchAll(/\bt\(\s*(['"])([^'"]+)\1/g)) {
        const key = match[2] ?? ''
        if (!resolves(key)) {
          missing.push(`${file}: ${key}`)
        }
      }
    }
    expect(missing).toEqual([])
  })
})