import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { assetsKey } from './assets'
import { findingsKey } from './findings'
import { dashboardQuery } from './reports'
import { scansKey } from './scans'
import type { components } from './schema'

/** ScanEvent is one frame of GET /api/events (§6). */
export type ScanEvent = components['schemas']['ScanEvent']

/** LiveScan is the newest event state for one asset. */
export type LiveScan = {
  status: ScanEvent['status']
  stage?: ScanEvent['stage']
  scanner?: string
  error?: string
}

const eventTypes = ['scan.queued', 'scan.progress', 'scan.finished'] as const

/**
 * useScanEvents keeps one EventSource open per mounted page and folds the
 * scan lifecycle into a per-asset map. The cookie-authenticated GET needs no
 * custom headers, and EventSource reconnects on its own; the server has no
 * replay, so a reconnect refetches the asset list instead.
 */
export function useScanEvents(): Map<number, LiveScan> {
  const queryClient = useQueryClient()
  const [live, setLive] = useState<Map<number, LiveScan>>(() => new Map())

  useEffect(() => {
    const source = new EventSource('/api/events')
    let openedBefore = false

    function onEvent(event: Event) {
      const data = parseScanEvent((event as MessageEvent<string>).data)
      if (!data) {
        return
      }

      setLive((previous) => {
        const next = new Map(previous)
        next.set(data.asset_id, {
          status: data.status,
          stage: data.stage,
          scanner: data.scanner,
          error: data.error,
        })
        return next
      })

      if (data.type === 'scan.finished') {
        void queryClient.invalidateQueries({ queryKey: assetsKey })
        void queryClient.invalidateQueries({ queryKey: scansKey })
        void queryClient.invalidateQueries({ queryKey: findingsKey })
        void queryClient.invalidateQueries({ queryKey: dashboardQuery.queryKey })
      }
    }

    for (const type of eventTypes) {
      source.addEventListener(type, onEvent)
    }

    // The first open is the initial connection. A later open means the stream
    // reconnected, so live state may be stale and finished events were missed.
    source.addEventListener('open', () => {
      if (!openedBefore) {
        openedBefore = true
        return
      }
      setLive(new Map())
      void queryClient.invalidateQueries({ queryKey: assetsKey })
    })

    return () => source.close()
  }, [queryClient])

  return live
}

/** parseScanEvent ignores comments, pings and frames that are not ScanEvents. */
function parseScanEvent(raw: string): ScanEvent | null {
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof value !== 'object' || value === null) {
    return null
  }

  const event = value as Partial<ScanEvent>
  if (
    typeof event.asset_id !== 'number' ||
    typeof event.scan_id !== 'number' ||
    typeof event.status !== 'string' ||
    !eventTypes.includes(event.type as (typeof eventTypes)[number])
  ) {
    return null
  }
  return event as ScanEvent
}
