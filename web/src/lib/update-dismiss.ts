const prefix = 'bastion:update-dismissed:'

/**
 * updateDismissKey scopes a dismissal to one release version, so a later
 * release still shows the notice.
 */
export function updateDismissKey(version: string): string {
  return `${prefix}${version}`
}

/** isUpdateDismissed reports whether this version's notice was dismissed. */
export function isUpdateDismissed(
  storage: Pick<Storage, 'getItem'>,
  version: string,
): boolean {
  return storage.getItem(updateDismissKey(version)) === '1'
}

/** dismissUpdate remembers the dismissal locally; it never leaves the browser. */
export function dismissUpdate(
  storage: Pick<Storage, 'setItem'>,
  version: string,
): void {
  storage.setItem(updateDismissKey(version), '1')
}
