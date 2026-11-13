/** suggestFix turns a scan error into a concrete next step (§7). */
export function suggestFix(error: string | undefined): string {
  const text = (error ?? '').toLowerCase()
  if (text.includes('token') || text.includes('401')) {
    return 'Re-test the GitHub connection on Connections.'
  }
  if (text.includes('rate limit')) {
    return 'Wait until GitHub resets the rate limit, then scan again.'
  }
  if (text.includes('not found') || text.includes('404')) {
    return 'Check the token has access to this repository.'
  }
  return 'See the Scans tab under Projects for details.'
}
