import { useSyncExternalStore } from 'react'

import { SettingSection } from './setting-section'
import { InfoTip } from './ui/info-tip'
import { languageOptions, setLanguage, useLanguage, useT } from '../lib/i18n'
import {
  fontFamilyOptions,
  fontSizeOptions,
  modeOptions,
  setFontFamily,
  setFontSize,
  setMode,
  setTheme,
  setWidth,
  storedFontFamily,
  storedFontSize,
  storedMode,
  storedTheme,
  storedWidth,
  subscribeAppearance,
  themeOptions,
  widthOptions,
  type FontFamily,
} from '../lib/theme'
import { cn } from '../lib/utils'

const choiceClass =
  'h-7 rounded-md border px-2.5 text-[0.8125rem] transition-colors'
const choiceOn = 'border-accent bg-accent text-accent-fg'
const choiceOff =
  'border-border-strong bg-surface text-muted hover:bg-hover hover:text-fg'

/**
 * AppearanceSettings is the Appearance tab (#142, #143): theme family,
 * light/dark mode, font family, font size and the interface language. Every
 * change is stored and applied at once, so the dialog itself is the live
 * preview.
 */
export function AppearanceSettings() {
  const t = useT()
  const language = useLanguage()
  const theme = useSyncExternalStore(subscribeAppearance, storedTheme)
  const mode = useSyncExternalStore(subscribeAppearance, storedMode)
  const family = useSyncExternalStore(subscribeAppearance, storedFontFamily)
  const size = useSyncExternalStore(subscribeAppearance, storedFontSize)
  const width = useSyncExternalStore(subscribeAppearance, storedWidth)

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div className="sm:col-span-2">
        <SettingSection title={t('appearance.theme.title')}>
          <div
            role="radiogroup"
            aria-label={t('appearance.theme.aria')}
            className="mt-1 grid grid-cols-2 gap-2 sm:grid-cols-3"
          >
            {themeOptions.map((option) => (
              <label
                key={option.value}
                className={cn(
                  'flex cursor-pointer flex-col gap-1.5 rounded-md border bg-bg p-2 transition-colors',
                  'has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-muted',
                  theme === option.value
                    ? 'border-accent bg-hover'
                    : 'border-border-subtle hover:bg-hover',
                )}
              >
                <input
                  type="radio"
                  name="appearance-theme"
                  value={option.value}
                  checked={theme === option.value}
                  onChange={() => setTheme(option.value)}
                  className="sr-only"
                />
                <span
                  aria-hidden="true"
                  className="theme-swatch"
                  data-theme-preview={option.value}
                >
                  <span
                    className="theme-swatch-half"
                    data-swatch-mode="light"
                  />
                  <span className="theme-swatch-half" data-swatch-mode="dark" />
                </span>
                <span className="text-[0.8125rem] font-medium">
                  {t(option.labelKey)}
                </span>
                <span className="text-[0.6875rem] leading-snug text-muted">
                  {t(option.hintKey)}
                </span>
              </label>
            ))}
          </div>
        </SettingSection>
      </div>

      <SettingSection
        title={t('appearance.mode.title')}
        tip={
          <InfoTip
            label={t('appearance.mode.hintAria')}
            content={t('appearance.mode.hint')}
          />
        }
      >
        <div
          role="group"
          aria-label={t('appearance.mode.aria')}
          className="mt-0.5 flex gap-1"
        >
          {modeOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={mode === option.value}
              onClick={() => setMode(option.value)}
              className={cn(
                choiceClass,
                mode === option.value ? choiceOn : choiceOff,
              )}
            >
              {t(option.labelKey)}
            </button>
          ))}
        </div>
      </SettingSection>

      <SettingSection
        title={t('appearance.fontFamily.title')}
        tip={
          <InfoTip
            label={t('appearance.fontFamily.hintAria')}
            content={t('appearance.fontFamily.hint')}
          />
        }
      >
        <select
          aria-label={t('appearance.fontFamily.aria')}
          value={family}
          onChange={(event) =>
            setFontFamily(event.target.value as FontFamily)
          }
          className="mt-0.5 h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
        >
          {fontFamilyOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {t(option.labelKey)}
            </option>
          ))}
        </select>
      </SettingSection>

      <SettingSection title={t('appearance.fontSize.title')}>
        <div
          role="group"
          aria-label={t('appearance.fontSize.aria')}
          className="mt-0.5 flex gap-1"
        >
          {fontSizeOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={size === option.value}
              onClick={() => setFontSize(option.value)}
              className={cn(
                choiceClass,
                size === option.value ? choiceOn : choiceOff,
              )}
            >
              {t(option.labelKey)}
            </button>
          ))}
        </div>
      </SettingSection>

      <SettingSection title={t('appearance.width.title')}>
        <div
          role="group"
          aria-label={t('appearance.width.title')}
          className="mt-0.5 flex gap-1"
        >
          {widthOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={width === option.value}
              onClick={() => setWidth(option.value)}
              className={cn(
                choiceClass,
                width === option.value ? choiceOn : choiceOff,
              )}
            >
              {t(option.labelKey)}
            </button>
          ))}
        </div>
      </SettingSection>

      <SettingSection
        title={t('appearance.language.title')}
        tip={
          <InfoTip
            label={t('appearance.language.hintAria')}
            content={t('appearance.language.hint')}
          />
        }
      >
        <select
          aria-label={t('appearance.language.aria')}
          value={language}
          onChange={(event) => setLanguage(event.target.value)}
          className="mt-0.5 h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
        >
          {languageOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </SettingSection>
    </div>
  )
}
