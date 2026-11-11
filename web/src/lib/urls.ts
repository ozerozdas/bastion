/** isHttpsUrl allows a reference to become a link only over https (§4.3). */
export function isHttpsUrl(value: string): boolean {
  return value.trim().toLowerCase().startsWith('https://')
}
