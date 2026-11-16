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
  label: string
  /** One line under the label: what the palette looks like. */
  hint: string
}

export const themeOptions = [
  {
    value: 'classic',
    label: 'Classic',
    hint: 'Today’s neutral look, light and dark.',
  },
  {
    value: 'claude',
    label: 'Claude',
    hint: 'Warm cream and terracotta.',
  },
  {
    value: 'contrast',
    label: 'High contrast',
    hint: 'Maximum text contrast, light and dark.',
  },
  {
    value: 'nord',
    label: 'Nord-style',
    hint: 'Cool blue-grey.',
  },
  {
    value: 'solarized',
    label: 'Solarized-style',
    hint: 'Warm paper and teal.',
  },
] as const satisfies readonly ThemeOption[]

export type ThemeName = (typeof themeOptions)[number]['value']

/** Mode is the user's choice; "system" follows the OS and is not resolved here. */
export type Mode = 'system' | 'light' | 'dark'
export type ResolvedMode = Exclude<Mode, 'system'>

export const modeOptions = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
] as const satisfies readonly { value: Mode; label: string }[]

/** FontFamily names the locally available stacks; nothing is downloaded. */
export type FontFamily = 'system' | 'humanist' | 'serif' | 'mono'

export const fontFamilyOptions = [
  { value: 'system', label: 'System' },
  { value: 'humanist', label: 'Humanist' },
  { value: 'serif', label: 'Serif' },
  { value: 'mono', label: 'Monospace' },
] as const satisfies readonly { value: FontFamily; label: string }[]

/** FontSize scales the root font size; the UI is sized in rem. */
export type FontSize = 'small' | 'default' | 'large' | 'xlarge'

export const fontSizeOptions = [
  { value: 'small', label: 'Small' },
  { value: 'default', label: 'Default' },
  { value: 'large', label: 'Large' },
  { value: 'xlarge', label: 'Extra large' },
] as const satisfies readonly { value: FontSize; label: string }[]

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
