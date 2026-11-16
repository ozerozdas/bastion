import type { LiveScan } from '../api/events'
import { t } from './i18n'

/** liveDetail names the scanner or stage the live event is on. */
export function liveDetail(live: LiveScan): string | null {
  const step = live.scanner ?? (live.stage ? stageLabel(live.stage) : null)
  return step ? `· ${step}` : null
}

/** stageLabel spells out the one stage whose wire name does not read as a step. */
export function stageLabel(stage: NonNullable<LiveScan['stage']>): string {
  return stage === 'wait_db' ? t('live.waitingDb') : stage
}

/** isLiveActive reports whether the live event describes a scan still in flight. */
export function isLiveActive(live: LiveScan | undefined): live is LiveScan {
  return live?.status === 'queued' || live?.status === 'running'
}
