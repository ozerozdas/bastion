/**
 * Manifest a fix plan step edits, derived from the scanner location (#47).
 *
 * The scanner usually reports the lockfile a package came from, so the dialog
 * shows the sibling manifest the pull request rewrites. The backend does the
 * same mapping; this copy only labels the confirmation dialog.
 */
const manifests: Record<string, Record<string, string>> = {
  go: { 'go.mod': 'go.mod', 'go.sum': 'go.mod' },
  npm: {
    'package.json': 'package.json',
    'package-lock.json': 'package.json',
    'yarn.lock': 'package.json',
    'pnpm-lock.yaml': 'package.json',
  },
}

/** manifestPath maps a finding location to the manifest for the ecosystem. */
export function manifestPath(
  ecosystem: string,
  location: string | undefined,
): string | undefined {
  if (!location) return undefined
  const file = locationPath(location)
  if (file === '') return undefined

  const slash = file.lastIndexOf('/')
  const dir = file.slice(0, slash + 1)
  const base = file.slice(slash + 1)
  const sibling = manifests[ecosystem.toLowerCase()]?.[base]
  return sibling === undefined ? undefined : dir + sibling
}

/** locationPath drops a ":line" or ":line:column" suffix and a leading "./". */
function locationPath(location: string): string {
  let file = location.trim()
  file = file.replace(/:\d+(?::\d+)?$/, '')
  return file.replace(/^\.\//, '')
}
