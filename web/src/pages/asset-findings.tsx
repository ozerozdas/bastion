import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from '@tanstack/react-router'

import { assetsQuery } from '../api/assets'
import { useScanEvents } from '../api/events'
import { useCancelScan, useStartScans } from '../api/scans'
import { ErrorNote } from '../components/error-note'
import { ScanScheduleSelect } from '../components/scan-schedule'
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { useT } from '../lib/i18n'
import { isLiveActive, liveDetail } from '../lib/live-scan'
import { FindingsPage } from './findings'
import { scanWhen, statusView } from './projects'

/** AssetFindingsPage reviews and rescans one asset from a single page (#182). */
export function AssetFindingsPage() {
  const t = useT()
  const { assetId } = useParams({ from: '/findings/$assetId' })
  const assets = useQuery(assetsQuery)
  const liveScans = useScanEvents()
  const start = useStartScans()
  const cancel = useCancelScan()

  const id = Number(assetId)
  const asset = assets.data?.find((item) => item.id === id)
  const live = liveScans.get(id)
  const lastScan = asset?.last_scan
  // A live event wins over the list row, so a failed rescan never shows the
  // previous scan's success.
  const liveActive = isLiveActive(live)
  const status = live?.status ?? lastScan?.status
  const running = status === 'queued' || status === 'running'

  return (
    <div className="flex flex-col gap-4">
      {asset ? (
        <section
          aria-label={asset.display_name}
          className="flex flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="truncate font-medium" title={asset.display_name}>
                {asset.display_name}
              </h2>
              <p className="truncate font-mono text-xs text-muted" title={asset.ref}>
                {asset.ref}
              </p>
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
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {status ? (
              <Badge tone={statusView[status].tone}>{t(statusView[status].labelKey)}</Badge>
            ) : (
              <Badge>{t('scanStatus.neverScanned')}</Badge>
            )}
            <span className="text-faint tabular-nums">{scanWhen(lastScan, running)}</span>
            {liveActive && live ? <span className="text-muted">{liveDetail(live)}</span> : null}
            <span className="ml-auto flex flex-wrap gap-1">
              {lastScan?.status === 'succeeded' ? (
                <Link
                  to="/scans/$scanId/diff"
                  params={{ scanId: String(lastScan.scan_id) }}
                  className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                >
                  {t('assetFindings.changes')}
                </Link>
              ) : null}
              <Link
                to="/findings/$assetId"
                params={{ assetId }}
                search={{ tab: 'fix-plan' }}
                className={buttonVariants({ variant: 'ghost', size: 'sm' })}
              >
                {t('findings.tabs.fixPlan')}
              </Link>
            </span>
          </div>
          {live?.status === 'failed' && live.error ? (
            <p role="alert" className="text-xs text-critical">
              {live.error}
            </p>
          ) : null}
          {start.error ? <ErrorNote error={start.error} /> : null}
          {cancel.error ? <ErrorNote error={cancel.error} /> : null}
        </section>
      ) : null}
      <FindingsPage />
    </div>
  )
}
