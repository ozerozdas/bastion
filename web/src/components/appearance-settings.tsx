import { useSyncExternalStore } from 'react'

import { SettingSection } from './setting-section'
import {
  fontFamilyOptions,
  fontSizeOptions,
  modeOptions,
  setFontFamily,
  setFontSize,
  setMode,
  setTheme,
  storedFontFamily,
  storedFontSize,
  storedMode,
  storedTheme,
  subscribeAppearance,
  themeOptions,
  type FontFamily,
} from '../lib/theme'
import { cn } from '../lib/utils'

const choiceClass =
  'h-7 rounded-md border px-2.5 text-[0.8125rem] transition-colors'
const choiceOn = 'border-accent bg-accent text-accent-fg'
const choiceOff =
  'border-border-strong bg-surface text-muted hover:bg-hover hover:text-fg'

/**
 * AppearanceSettings is the Appearance tab (#142): theme family, light/dark
 * mode, font family and font size. Every change is stored and applied at once,
 * so the dialog itself is the live preview.
 */
export function AppearanceSettings() {
  const theme = useSyncExternalStore(subscribeAppearance, storedTheme)
  const mode = useSyncExternalStore(subscribeAppearance, storedMode)
  const family = useSyncExternalStore(subscribeAppearance, storedFontFamily)
  const size = useSyncExternalStore(subscribeAppearance, storedFontSize)

  return (
    <div className="flex flex-col gap-3">
      <SettingSection title="Theme">
        <div
          role="radiogroup"
          aria-label="Theme"
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
                {option.label}
              </span>
              <span className="text-[0.6875rem] leading-snug text-muted">
                {option.hint}
              </span>
            </label>
          ))}
        </div>
      </SettingSection>

      <SettingSection title="Mode">
        <div role="group" aria-label="Colour mode" className="mt-0.5 flex gap-1">
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
              {option.label}
            </button>
          ))}
        </div>
        <p className="text-[0.6875rem] text-muted">
          System follows your operating system&rsquo;s light or dark setting.
        </p>
      </SettingSection>

      <SettingSection title="Font family">
        <select
          aria-label="Font family"
          value={family}
          onChange={(event) =>
            setFontFamily(event.target.value as FontFamily)
          }
          className="mt-0.5 h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
        >
          {fontFamilyOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <p className="text-[0.6875rem] text-muted">
          Locally installed stacks only; no font is downloaded.
        </p>
      </SettingSection>

      <SettingSection title="Font size">
        <div role="group" aria-label="Font size" className="mt-0.5 flex gap-1">
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
              {option.label}
            </button>
          ))}
        </div>
      </SettingSection>
    </div>
  )
}
