import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * English is the fallback for a key a translation does not carry yet. Every
 * shipped locale has the full key set (i18n.test.ts proves it), so this test
 * removes one key from the Turkish file to exercise the fallback path.
 */
vi.mock('../locales/tr.json', async (importOriginal) => {
  const real =
    await importOriginal<{ default: Record<string, string> }>()
  const { 'nav.findings': _dropped, ...rest } = real.default
  return { default: rest }
})

import { setLanguage, t } from './i18n'

describe('t() fallback', () => {
  beforeEach(() => {
    setLanguage('tr')
  })

  it('uses the active language when it has the key', () => {
    expect(t('nav.dashboard')).toBe('Pano')
  })

  it('falls back to English for a key the active language lacks', () => {
    expect(t('nav.findings')).toBe('Findings')
  })

  it('returns the key itself when no language has it', () => {
    expect(t('nav.noSuchKey')).toBe('nav.noSuchKey')
  })
})
