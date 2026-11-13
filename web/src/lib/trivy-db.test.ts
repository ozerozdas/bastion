import { describe, expect, it } from 'vitest'

import { trivyDBView } from './trivy-db'

describe('trivyDBView', () => {
  it('renders nothing until the status arrives', () => {
    expect(trivyDBView(undefined)).toEqual({ kind: 'hidden' })
  })

  it('renders nothing when the DB is ready', () => {
    expect(
      trivyDBView({ state: 'ready', updated_at: '2026-05-01T12:00:00Z' }),
    ).toEqual({ kind: 'hidden' })
  })

  it('offers the download when the DB is missing', () => {
    expect(trivyDBView({ state: 'missing' })).toEqual({ kind: 'missing' })
  })

  it('marks a download a scan started', () => {
    expect(trivyDBView({ state: 'downloading', trigger: 'scan' })).toEqual({
      kind: 'downloading',
      fromScan: true,
    })
  })

  it('does not blame a scan when the user started it', () => {
    expect(trivyDBView({ state: 'downloading', trigger: 'user' })).toEqual({
      kind: 'downloading',
      fromScan: false,
    })
    expect(trivyDBView({ state: 'downloading' })).toEqual({
      kind: 'downloading',
      fromScan: false,
    })
  })

  it('carries the error of a failed download', () => {
    expect(
      trivyDBView({ state: 'failed', error: 'dial tcp: no such host' }),
    ).toEqual({ kind: 'failed', error: 'dial tcp: no such host' })
    expect(trivyDBView({ state: 'failed' })).toEqual({
      kind: 'failed',
      error: undefined,
    })
  })
})
