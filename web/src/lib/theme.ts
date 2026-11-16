/**
 * Appearance preferences (#142): the theme family, the light/dark mode, the
 * font family and the font size. They live in localStorage and are applied to
 * <html> as data-theme, data-mode, data-font and data-font-size; styles.css
 * keys every palette on [data-theme][data-mode], so the whole app follows
 * without a component knowing about it.
 */

/** ThemeOption is one palette family in the Appearance tab. */
export type ThemeOption = {
  value: string
  /** Translation key of the palette's name. */
  labelKey: string
  /** Translation key of the line under it: what the palette looks like. */
  hintKey: string
}

export const themeOptions = [
  {
    value: 'classic',
    labelKey: 'theme.classic.label',
    hintKey: 'theme.classic.hint',
  },
  {
    value: 'claude',
    labelKey: 'theme.claude.label',
    hintKey: 'theme.claude.hint',
  },
  {
    value: 'contrast',
    labelKey: 'theme.contrast.label',
    hintKey: 'theme.contrast.hint',
  },
  {
    value: 'nord',
    labelKey: 'theme.nord.label',
    hintKey: 'theme.nord.hint',
  },
  {
    value: 'solarized',
    labelKey: 'theme.solarized.label',
    hintKey: 'theme.solarized.hint',
  },
] as const satisfies readonly ThemeOption[]

export type ThemeName = (typeof themeOptions)[number]['value']

/** Mode is the user's choice; "system" follows the OS and is not resolved here. */
export type Mode = 'system' | 'light' | 'dark'
export type ResolvedMode = Exclude<Mode, 'system'>

export const modeOptions = [
  { value: 'system', labelKey: 'mode.system' },
  { value: 'light', labelKey: 'mode.light' },
  { value: 'dark', labelKey: 'mode.dark' },
] as const satisfies readonly { value: Mode; labelKey: string }[]

/** FontFamily names the locally available stacks; nothing is downloaded. */
export type FontFamily = 'system' | 'humanist' | 'serif' | 'mono'

export const fontFamilyOptions = [
  { value: 'system', labelKey: 'font.system' },
  { value: 'humanist', labelKey: 'font.humanist' },
  { value: 'serif', labelKey: 'font.serif' },
  { value: 'mono', labelKey: 'font.mono' },
] as const satisfies readonly { value: FontFamily; labelKey: string }[]

/** FontSize scales the root font size; the UI is sized in rem. */
export type FontSize = 'small' | 'default' | 'large' | 'xlarge'

export const fontSizeOptions = [
  { value: 'small', labelKey: 'fontSize.small' },
  { value: 'default', labelKey: 'fontSize.default' },
  { value: 'large', labelKey: 'fontSize.large' },
  { value: 'xlarge', labelKey: 'fontSize.xlarge' },
] as const satisfies readonly { value: FontSize; labelKey: string }[]

const themeKey = 'bastion-theme'
const modeKey = 'bastion-mode'
const fontFamilyKey = 'bastion-font-family'
const fontSizeKey = 'bastion-font-size'

type Option<T extends string> = readonly { value: T }[]

/** storedOption reads a key and falls back when it holds an unknown value. */
function storedOption<T extends string>(
  key: string,
  options: Option<T>,
  fallback: T,
): T {
  const value = localStorage.getItem(key)
  return options.some((option) => option.value === value)
    ? (value as T)
    : fallback
}

/** storedTheme is the palette family; the pre-#142 key is now the mode. */
export function storedTheme(): ThemeName {
  return storedOption(themeKey, themeOptions, 'classic')
}

/**
 * storedMode is System, Light or Dark. Before #142 the bastion-theme key held
 * a light/dark pin, so that value still means what it meant.
 */
export function storedMode(): Mode {
  const mode = localStorage.getItem(modeKey)
  if (mode === 'system' || mode === 'light' || mode === 'dark') {
    return mode
  }
  const legacy = localStorage.getItem(themeKey)
  return legacy === 'light' || legacy === 'dark' ? legacy : 'system'
}

export function storedFontFamily(): FontFamily {
  return storedOption(fontFamilyKey, fontFamilyOptions, 'system')
}

export function storedFontSize(): FontSize {
  return storedOption(fontSizeKey, fontSizeOptions, 'default')
}

/** resolveMode turns the System choice into the OS preference. */
export function resolveMode(mode: Mode): ResolvedMode {
  if (mode !== 'system') {
    return mode
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark'
    : 'light'
}

/** applyAppearance writes the stored preferences onto <html>. */
export function applyAppearance(): void {
  const root = document.documentElement
  root.dataset.theme = storedTheme()
  root.dataset.mode = resolveMode(storedMode())
  root.dataset.font = storedFontFamily()
  root.dataset.fontSize = storedFontSize()
}

const listeners = new Set<() => void>()

/** subscribeAppearance notifies when a preference changes or the OS flips. */
export function subscribeAppearance(listener: () => void): () => void {
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

function save(key: string, value: string): void {
  localStorage.setItem(key, value)
  applyAppearance()
  notify()
}

export function setTheme(theme: ThemeName): void {
  save(themeKey, theme)
}

export function setMode(mode: Mode): void {
  save(modeKey, mode)
}

export function setFontFamily(family: FontFamily): void {
  save(fontFamilyKey, family)
}

export function setFontSize(size: FontSize): void {
  save(fontSizeKey, size)
}

/**
 * installAppearance applies the stored preferences before the first render and
 * keeps System mode in step with the OS while the app is open.
 */
export function installAppearance(): void {
  applyAppearance()
  const media = window.matchMedia('(prefers-color-scheme: dark)')
  media.addEventListener('change', () => {
    if (storedMode() === 'system') {
      applyAppearance()
      notify()
    }
  })
}
