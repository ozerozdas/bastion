import { describe, expect, it } from 'vitest'

import {
  dismissGetStarted,
  getStartedState,
  isCliStepDone,
  isGetStartedDismissed,
  markCliStepDone,
  type GetStartedInput,
} from './get-started'

/** input is the checklist with nothing done, so each test changes one fact. */
const input: GetStartedInput = {
  connectionCount: 0,
  assetCount: 0,
  hasSucceededScan: false,
  cliDone: false,
  dismissed: false,
}

/** fakeStorage is the two localStorage methods the helpers use. */
function fakeStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial))
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value)
    },
  }
}

describe('getStartedState', () => {
  it('shows four open steps on a fresh install', () => {
    const state = getStartedState(input)

    expect(state.visible).toBe(true)
    expect(state.doneCount).toBe(0)
    expect(state.total).toBe(4)
    expect(state.steps.map((step) => step.id)).toEqual([
      'connect-github',
      'add-project',
      'run-scan',
      'scan-in-ci',
    ])
    expect(state.steps.every((step) => !step.done)).toBe(true)
    expect(state.steps[0]?.to).toBe('/connections')
    expect(state.steps[1]?.to).toBe('/projects')
    expect(state.steps[2]?.to).toBe('/projects')
    expect(state.steps[3]?.href).toContain('CLI-Reference.md')
  })

  it('ticks the steps the existing data covers and stays visible', () => {
    const state = getStartedState({
      ...input,
      connectionCount: 1,
      assetCount: 2,
      hasSucceededScan: true,
    })

    expect(state.doneCount).toBe(3)
    expect(state.visible).toBe(true)
    expect(
      state.steps.filter((step) => step.done).map((step) => step.id),
    ).toEqual(['connect-github', 'add-project', 'run-scan'])
  })

  it('ticks the scan step only after a succeeded scan', () => {
    const queued = getStartedState({ ...input, assetCount: 1 })
    expect(queued.steps[2]?.done).toBe(false)

    const succeeded = getStartedState({
      ...input,
      assetCount: 1,
      hasSucceededScan: true,
    })
    expect(succeeded.steps[2]?.done).toBe(true)
  })

  it('hides the card when every step is done', () => {
    const state = getStartedState({
      connectionCount: 1,
      assetCount: 1,
      hasSucceededScan: true,
      cliDone: true,
      dismissed: false,
    })

    expect(state.doneCount).toBe(4)
    expect(state.visible).toBe(false)
  })

  it('hides the card when dismissed, even with steps open', () => {
    const state = getStartedState({
      ...input,
      connectionCount: 1,
      dismissed: true,
    })

    expect(state.doneCount).toBe(1)
    expect(state.visible).toBe(false)
  })
})

describe('get started storage', () => {
  it('remembers the CLI step without dismissing the card', () => {
    const storage = fakeStorage()
    expect(isCliStepDone(storage)).toBe(false)
    expect(isGetStartedDismissed(storage)).toBe(false)

    markCliStepDone(storage)

    expect(isCliStepDone(storage)).toBe(true)
    expect(isGetStartedDismissed(storage)).toBe(false)
  })

  it('remembers the dismissal locally', () => {
    const storage = fakeStorage()
    expect(isGetStartedDismissed(storage)).toBe(false)

    dismissGetStarted(storage)

    expect(isGetStartedDismissed(storage)).toBe(true)
    expect(isCliStepDone(storage)).toBe(false)
  })
})
