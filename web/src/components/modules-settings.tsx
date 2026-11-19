import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { eolQuery, useSetEOLEnabled } from '../api/eol'
import { epssQuery, useSetEPSSEnabled } from '../api/epss'
import { outdatedQuery, useSetOutdatedEnabled } from '../api/outdated'
import {
  reachabilityQuery,
  useSetReachabilityEnabled,
} from '../api/reachability'
import { sastQuery, useSetSASTEnabled } from '../api/sast'
import { updateQuery, useSetUpdateConsent } from '../api/update'
import { formatNumber, useT } from '../lib/i18n'
import { cn } from '../lib/utils'
import { Badge } from './ui/badge'
import { InfoTip } from './ui/info-tip'
import { Switch } from './ui/switch'

const cardClass =
  'flex h-full w-full flex-col gap-2 rounded-card border border-border-subtle bg-surface p-4'
const bodyClass = 'line-clamp-2 text-xs leading-relaxed text-muted'

/**
 * ModulesSettings is Configuration's Modules tab (#139): the opt-in scanners
 * and data sources as a card grid. Each card says what the module does and
 * what it downloads, separates the state (a badge) from the switch, and keeps
 * its newest result as a faint footer.
 */
export function ModulesSettings() {
  return (
    <ul className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      <EPSSCard />
      <ReachabilityCard />
      <OutdatedCard />
      <EOLCard />
      <SASTCard />
      <ReleaseCheckCard />
    </ul>
  )
}

/** ModuleCard is one module's card: name, state, switch, body and footer. */
function ModuleCard({
  title,
  body,
  on,
  pending,
  onChange,
  footer,
  muted = false,
  children,
}: {
  title: string
  body: string
  on: boolean
  pending: boolean
  onChange: (enabled: boolean) => void
  /** The module's newest result, kept at the card's bottom. */
  footer?: ReactNode
  /** A module that cannot run here is muted, like an absent Docker daemon. */
  muted?: boolean
  children?: ReactNode
}) {
  const t = useT()

  return (
    <section aria-label={title} className={cn(cardClass, muted && 'opacity-60')}>
      <div className="flex items-center gap-2">
        <h3 className="min-w-0 truncate text-[0.8125rem] font-semibold">
          {title}
        </h3>
        <Badge tone={on ? 'ok' : 'neutral'}>
          {on ? t('settings.badge.on') : t('settings.badge.off')}
        </Badge>
        <InfoTip
          label={t('settings.module.about', { title })}
          content={body}
        />
        <div className="-my-1 -mr-1 ml-auto">
          <Switch
            label={title}
            checked={on}
            disabled={pending}
            onCheckedChange={onChange}
          />
        </div>
      </div>

      <p className={bodyClass}>{body}</p>
      {children}

      {footer === undefined ? (
        <span className="mt-auto" />
      ) : (
        <p className="mt-auto pt-1 text-xs text-faint">{footer}</p>
      )}
    </section>
  )
}

function EPSSCard() {
  const t = useT()
  const { data } = useQuery(epssQuery)
  const toggle = useSetEPSSEnabled()

  if (!data) {
    return null
  }

  const failed = data.enabled && data.error !== undefined
  const downloading = data.enabled && !failed && data.count === undefined
  const meta =
    data.enabled && !failed && data.count !== undefined
      ? `${t('settings.epss.cves', { count: formatNumber(data.count) })}${
          data.score_date ? ` · ${data.score_date.slice(0, 10)}` : ''
        }`
      : undefined

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.epss.title')}
        body={t('settings.epss.body')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
        footer={meta}
      >
        {failed ? (
          <>
            <p className="text-[0.6875rem] text-critical">
              {t('settings.epss.failed')}
            </p>
            <p
              className="min-w-0 truncate font-mono text-[0.625rem] text-muted"
              title={data.error}
            >
              {data.error}
            </p>
            <p className="text-[0.6875rem] text-faint">
              {t('settings.epss.retries')}
            </p>
          </>
        ) : downloading ? (
          <p className="font-mono text-[0.6875rem] text-muted">
            {t('settings.epss.downloading')}
          </p>
        ) : null}
      </ModuleCard>
    </li>
  )
}

function ReachabilityCard() {
  const t = useT()
  const { data } = useQuery(reachabilityQuery)
  const toggle = useSetReachabilityEnabled()

  if (!data) {
    return null
  }

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.reach.title')}
        body={t('settings.reach.body')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
        muted={!data.available}
        footer={data.enabled && data.available ? t('settings.reach.running') : undefined}
      >
        {data.enabled && !data.available ? (
          <>
            <p className="text-[0.6875rem] text-critical">
              {t('settings.reach.noToolchain')}
            </p>
            <p className="text-[0.6875rem] text-faint">
              {t('settings.reach.install')}
            </p>
          </>
        ) : null}
      </ModuleCard>
    </li>
  )
}

function OutdatedCard() {
  const t = useT()
  const { data } = useQuery(outdatedQuery)
  const toggle = useSetOutdatedEnabled()

  if (!data) {
    return null
  }

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.outdated.title')}
        body={t('settings.outdated.body')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </li>
  )
}

function EOLCard() {
  const t = useT()
  const { data } = useQuery(eolQuery)
  const toggle = useSetEOLEnabled()

  if (!data) {
    return null
  }

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.eol.title')}
        body={t('settings.eol.body')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </li>
  )
}

function SASTCard() {
  const t = useT()
  const { data } = useQuery(sastQuery)
  const toggle = useSetSASTEnabled()

  if (!data) {
    return null
  }

  const footer = !data.enabled
    ? undefined
    : data.installing
      ? t('settings.sast.downloading', { version: data.version })
      : data.install_error
        ? t('settings.sast.failed')
        : data.state === 'installed'
          ? t('settings.sast.installed', { version: data.version })
          : t('settings.sast.notInstalled')

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.sast.title')}
        body={t('settings.sast.body', { version: data.version })}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
        footer={footer}
      >
        {data.enabled && data.install_error ? (
          <>
            <p className="text-[0.6875rem] text-critical">
              {t('settings.sast.failed')}
            </p>
            <p
              className="min-w-0 truncate font-mono text-[0.625rem] text-muted"
              title={data.install_error}
            >
              {data.install_error}
            </p>
          </>
        ) : null}
      </ModuleCard>
    </li>
  )
}

function ReleaseCheckCard() {
  const t = useT()
  const { data } = useQuery(updateQuery)
  const consent = useSetUpdateConsent()

  // Disabled (env switch, CI, dev build): offering it would promise a check
  // that cannot run.
  if (!data || data.disabled) {
    return null
  }

  const on = data.consent === 'on'
  const footer =
    on && data.update_available && data.latest
      ? t('settings.release.available', {
          version: data.latest.startsWith('v')
            ? data.latest
            : `v${data.latest}`,
        })
      : undefined

  return (
    <li className="flex">
      <ModuleCard
        title={t('settings.release.title')}
        body={t('settings.release.body')}
        on={on}
        pending={consent.isPending}
        onChange={(enabled) => consent.mutate(enabled)}
        footer={footer}
      />
    </li>
  )
}
