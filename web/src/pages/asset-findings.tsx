import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from '@tanstack/react-router'
import { useRef } from 'react'

import { assetsQuery, type Asset } from '../api/assets'
import { useScanEvents } from '../api/events'
import { licencePolicyQuery } from '../api/licence-policy'
import { useCancelScan, useStartScans } from '../api/scans'
import { ErrorNote } from '../components/error-note'
import { LicencePolicyEditor } from '../components/licence-policy-card'
import { ScanScheduleSelect } from '../components/scan-schedule'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { useT } from '../lib/i18n'
import { isLiveActive, liveDetail } from '../lib/live-scan'
import { FindingsPage } from './findings'
import { scanWhen, statusView } from './projects'

/**
 * AssetFindingsPage reviews and rescans one asset from a single page (#182).
 * The project's summary is the hero: it shares a card with the tab row.
 */
export function AssetFindingsPage() {
  const { assetId } = useParams({ from: '/findings/$assetId' })
  const assets = useQuery(assetsQuery)
  const asset = assets.data?.find((item) => item.id === Number(assetId))

  return <FindingsPage hero={asset ? <AssetHero asset={asset} /> : undefined} />
}

function AssetHero({ asset }: { asset: Asset }) {
  const t = useT()
  const liveScans = useScanEvents()
  const start = useStartScans()
  const cancel = useCancelScan()
  const live = liveScans.get(asset.id)
  const lastScan = asset.last_scan
  // A live event wins over the list row, so a failed rescan never shows the
  // previous scan's success.
  const liveActive = isLiveActive(live)
  const status = live?.status ?? lastScan?.status
  const running = status === 'queued' || status === 'running'

  return (
    <section aria-label={asset.display_name} className="flex flex-col gap-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-[1.0625rem] font-semibold" title={asset.display_name}>
            {asset.display_name}
          </h2>
          {asset.ref === asset.display_name ? null : (
            <p className="truncate font-mono text-xs text-muted" title={asset.ref}>
              {asset.ref}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <ScanScheduleSelect asset={asset} />
          {running && lastScan ? (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => cancel.mutate(lastScan.scan_id)}
              disabled={cancel.isPending}
            >
              {cancel.isPending ? t('repos.canceling') : t('repos.cancel')}
            </Button>
          ) : null}
          <Button
            type="button"
            size="sm"
            onClick={() => start.mutate([asset.id])}
            disabled={start.isPending || running}
          >
            {start.isPending ? t('repos.queueing') : t('assetFindings.rescan')}
          </Button>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
        <span className="flex items-center gap-1.5">
          {status ? (
            <Badge tone={statusView[status].tone}>{t(statusView[status].labelKey)}</Badge>
          ) : (
            <Badge>{t('scanStatus.neverScanned')}</Badge>
          )}
          <span className="text-faint tabular-nums">{scanWhen(lastScan, running)}</span>
        </span>
        {liveActive && live ? <span className="text-muted">{liveDetail(live)}</span> : null}
        {lastScan?.status === 'succeeded' ? (
          <Link
            to="/scans/$scanId/diff"
            params={{ scanId: String(lastScan.scan_id) }}
            className="text-muted hover:text-fg hover:underline"
          >
            {t('assetFindings.changes')}
          </Link>
        ) : null}
        <LicenceChip asset={asset} />
      </div>
      {live?.status === 'failed' && live.error ? (
        <p role="alert" className="text-xs text-critical">
          {live.error}
        </p>
      ) : null}
      {start.error ? <ErrorNote error={start.error} /> : null}
      {cancel.error ? <ErrorNote error={cancel.error} /> : null}
    </section>
  )
}

/**
 * LicenceChip shows the project's licence policy in one line and edits it in
 * a dialog, since it changes rarely and need not hold a card on the page.
 */
function LicenceChip({ asset }: { asset: Asset }) {
  const t = useT()
  const { data } = useQuery(licencePolicyQuery(asset.id))
  // ponytail: native <dialog> gives the focus trap, Escape and backdrop for free.
  const dialog = useRef<HTMLDialogElement>(null)
  if (!data) {
    return null
  }
  const allowed = data.allow.length
  const denied = data.deny.length
  const title = t('licence.forProject', { project: asset.display_name })

  return (
    <>
      <button
        type="button"
        onClick={() => dialog.current?.showModal()}
        className="text-muted hover:text-fg hover:underline"
      >
        {t('assetFindings.licence', {
          summary:
            allowed === 0 && denied === 0
              ? t('licence.noRulesAsset')
              : t('licence.counts', { allowed, denied }),
        })}
      </button>
      <dialog
        ref={dialog}
        aria-label={title}
        // Clicking the backdrop lands on the dialog element itself.
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close()
        }}
        className="m-auto w-[min(480px,calc(100vw-2rem))] rounded-xl border border-border-subtle bg-surface p-5 text-fg shadow-xl backdrop:bg-black/40"
      >
        <div className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-[0.9375rem] font-semibold">{title}</h2>
            <button
              type="button"
              onClick={() => dialog.current?.close()}
              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
            >
              {t('common.close')}
            </button>
          </div>
          <LicencePolicyEditor assetId={asset.id} policy={data} />
        </div>
      </dialog>
    </>
  )
}
