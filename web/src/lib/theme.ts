export type Theme = 'light' | 'dark'

const storageKey = 'bastion-theme'

/** storedTheme is the user's pinned choice, or undefined to follow the OS. */
export function storedTheme(): Theme | undefined {
  const value = localStorage.getItem(storageKey)
  return value === 'light' || value === 'dark' ? value : undefined
}

/** currentTheme is what is on screen now: the pinned choice, else the OS preference. */
export function currentTheme(): Theme {
  return (
    storedTheme() ??
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  )
}

/** applyTheme pins a theme; styles.css switches color-scheme on data-theme. */
export function applyTheme(theme: Theme | undefined): void {
  if (theme) {
    localStorage.setItem(storageKey, theme)
    document.documentElement.dataset.theme = theme
  } else {
    delete document.documentElement.dataset.theme
  }
}
