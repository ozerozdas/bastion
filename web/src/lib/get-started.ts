/** GetStartedStepId names the four steps, in the order they are shown. */
export type GetStartedStepId =
  | 'connect-github'
  | 'add-project'
  | 'run-scan'
  | 'scan-in-ci'

/** GetStartedStep is one row of the checklist. */
export type GetStartedStep = {
  id: GetStartedStepId
  title: string
  hint: string
  done: boolean
  /** In-app route where the step is done; absent for the CLI step. */
  to?: '/connections' | '/projects'
  /** Documentation link; only the CLI step has one. */
  href?: string
}

/** GetStartedInput is the existing data the checklist ticks from. */
export type GetStartedInput = {
  connectionCount: number
  assetCount: number
  hasSucceededScan: boolean
  /** The CLI step has no data behind it: the user marks it done. */
  cliDone: boolean
  dismissed: boolean
}

/** GetStartedState is the card's steps and whether the card is shown. */
export type GetStartedState = {
  steps: GetStartedStep[]
  doneCount: number
  total: number
  /** Hidden when every step is done or the card was dismissed. */
  visible: boolean
}

const cliReferenceUrl =
  'https://github.com/ozerozdas/bastion/blob/master/docs/wiki/CLI-Reference.md'

/**
 * getStartedState ticks each step from data the app already has. It is pure so
 * every combination is testable without a DOM or a network call.
 */
export function getStartedState(input: GetStartedInput): GetStartedState {
  const steps: GetStartedStep[] = [
    {
      id: 'connect-github',
      title: 'Connect GitHub',
      hint: 'Paste a read-only token on Connections; it stays in the OS keychain.',
      done: input.connectionCount > 0,
      to: '/connections',
    },
    {
      id: 'add-project',
      title: 'Add a project',
      hint: 'Pick a repository or an absolute path on this machine in Projects.',
      done: input.assetCount > 0,
      to: '/projects',
    },
    {
      id: 'run-scan',
      title: 'Run the first scan',
      hint: 'Select a project in Projects and press Scan; findings appear when it finishes.',
      done: input.hasSucceededScan,
      to: '/projects',
    },
    {
      id: 'scan-in-ci',
      title: 'Scan in CI or from the CLI',
      hint: 'Keep scanning on every push with the CLI reference.',
      done: input.cliDone,
      href: cliReferenceUrl,
    },
  ]

  const doneCount = steps.filter((step) => step.done).length
  const total = steps.length

  return {
    steps,
    doneCount,
    total,
    visible: !input.dismissed && doneCount < total,
  }
}

const cliDoneKey = 'bastion:get-started:cli-done'
const dismissedKey = 'bastion:get-started:dismissed'

/** isCliStepDone reports whether the user marked the CLI step done. */
export function isCliStepDone(storage: Pick<Storage, 'getItem'>): boolean {
  return storage.getItem(cliDoneKey) === '1'
}

/** markCliStepDone remembers the CLI step locally; it never leaves the browser. */
export function markCliStepDone(storage: Pick<Storage, 'setItem'>): void {
  storage.setItem(cliDoneKey, '1')
}

/** isGetStartedDismissed reports whether the whole card was dismissed. */
export function isGetStartedDismissed(
  storage: Pick<Storage, 'getItem'>,
): boolean {
  return storage.getItem(dismissedKey) === '1'
}

/** dismissGetStarted hides the card in this browser only. */
export function dismissGetStarted(storage: Pick<Storage, 'setItem'>): void {
  storage.setItem(dismissedKey, '1')
}
