import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { epssQuery, useSetEPSSEnabled } from '../api/epss'
import { licencePolicyQuery } from '../api/licence-policy'
import { outdatedQuery, useSetOutdatedEnabled } from '../api/outdated'
import { reachabilityQuery, useSetReachabilityEnabled } from '../api/reachability'
import { sastQuery, useSetSASTEnabled } from '../api/sast'
import { updateQuery, useSetUpdateConsent } from '../api/update'
import { formatNumber, useT } from '../lib/i18n'
import { AppearanceSettings } from './appearance-settings'
import { useDrawerFocus } from './drawer-focus'
import { LicencePolicyEditor } from './licence-policy-card'
import { SettingSection } from './setting-section'
import { Button } from './ui/button'
import { Tabs, type TabItem } from './ui/tabs'

type ConfigurationTab = 'modules' | 'appearance'

/**
 * SettingsDialog is the Configuration modal (#139, #142, #143): the opt-in
 * modules and the global policy that used to be sidebar cards, plus the
 * appearance and language preferences. Each module says what it does and what
 * it downloads before the user turns it on, and separates the state (a badge)
 * from the action (a button).
 */
export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const t = useT()
  const { panel, onKeyDown } = useDrawerFocus(onClose)
  const [tab, setTab] = useState<ConfigurationTab>('modules')
  const configurationTabs: TabItem<ConfigurationTab>[] = [
    { value: 'modules', label: t('settings.tabs.modules') },
    { value: 'appearance', label: t('settings.tabs.appearance') },
  ]

  return (
    <div className="fixed inset-0 z-40">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="absolute inset-0 overlay-scrim"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="configuration-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="absolute inset-x-4 top-[8vh] mx-auto flex max-h-[84vh] max-w-[640px] flex-col gap-4 overflow-y-auto rounded-xl border border-border-subtle bg-surface p-5 shadow-xl focus:outline-none"
      >
        <div className="flex items-start gap-3">
          <div className="flex flex-col gap-0.5">
            <h2 id="configuration-title" className="text-[0.9375rem] font-semibold">
              {t('settings.title')}
            </h2>
            <p className="text-xs text-muted">{t('settings.subtitle')}</p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="ml-auto shrink-0"
            onClick={onClose}
          >
            {t('common.close')}
          </Button>
        </div>

        <Tabs
          label={t('settings.tabs.aria')}
          items={configurationTabs}
          value={tab}
          onChange={setTab}
        >
          {tab === 'appearance' ? (
            <AppearanceSettings />
          ) : (
            <div className="flex flex-col gap-3">
              <EPSSToggle />
              <ReachabilityToggle />
              <OutdatedToggle />
              <SASTToggle />
              <LicencePolicySection />
              <ReleaseCheckSection />
            </div>
          )}
        </Tabs>
      </div>
    </div>
  )
}

/** ToggleButton is the action, named for its setting so repeated labels differ. */
function ToggleButton({
  title,
  on,
  pending,
  onChange,
}: {
  title: string
  on: boolean
  pending: boolean
  onChange: (enabled: boolean) => void
}) {
  const t = useT()
  return (
    <Button
      type="button"
      size="sm"
      variant={on ? 'outline' : 'default'}
      className="mt-0.5 self-start"
      aria-label={t('settings.toggle.aria', {
        action: on
          ? t('settings.toggle.action.off')
          : t('settings.toggle.action.on'),
        title,
      })}
      disabled={pending}
      onClick={() => onChange(!on)}
    >
      {on ? t('settings.toggle.on') : t('settings.toggle.off')}
    </Button>
  )
}

function EPSSToggle() {
  const t = useT()
  const { data } = useQuery(epssQuery)
  const toggle = useSetEPSSEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.epss.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.epss.body')}
      </p>
      {data.enabled ? (
        data.error ? (
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
        ) : data.count === undefined ? (
          <p className="font-mono text-[0.6875rem] text-muted">
            {t('settings.epss.downloading')}
          </p>
        ) : (
          <p className="text-[0.6875rem] text-muted">
            <span className="tabular-nums">
              {t('settings.epss.cves', { count: formatNumber(data.count) })}
            </span>
            {data.score_date ? ` · ${data.score_date.slice(0, 10)}` : ''}
          </p>
        )
      ) : null}
      <ToggleButton
        title={t('settings.epss.title')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function ReachabilityToggle() {
  const t = useT()
  const { data } = useQuery(reachabilityQuery)
  const toggle = useSetReachabilityEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.reach.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.reach.body')}
      </p>
      {data.enabled ? (
        data.available ? (
          <p className="text-[0.6875rem] text-muted">
            {t('settings.reach.running')}
          </p>
        ) : (
          <>
            <p className="text-[0.6875rem] text-critical">
              {t('settings.reach.noToolchain')}
            </p>
            <p className="text-[0.6875rem] text-faint">
              {t('settings.reach.install')}
            </p>
          </>
        )
      ) : null}
      <ToggleButton
        title={t('settings.reach.title')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function OutdatedToggle() {
  const t = useT()
  const { data } = useQuery(outdatedQuery)
  const toggle = useSetOutdatedEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.outdated.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.outdated.body')}
      </p>
      <ToggleButton
        title={t('settings.outdated.title')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function SASTToggle() {
  const t = useT()
  const { data } = useQuery(sastQuery)
  const toggle = useSetSASTEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.sast.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.sast.body', { version: data.version })}
      </p>
      {data.enabled ? (
        data.installing ? (
          <p className="font-mono text-[0.6875rem] text-muted">
            {t('settings.sast.downloading', { version: data.version })}
          </p>
        ) : data.install_error ? (
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
        ) : data.state === 'installed' ? (
          <p className="text-[0.6875rem] text-muted">
            {t('settings.sast.installed', { version: data.version })}
          </p>
        ) : (
          <p className="text-[0.6875rem] text-muted">
            {t('settings.sast.notInstalled')}
          </p>
        )
      ) : null}
      <ToggleButton
        title={t('settings.sast.title')}
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function LicencePolicySection() {
  const t = useT()
  const { data } = useQuery(licencePolicyQuery())

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.licence.title')}>
      <LicencePolicyEditor
        policy={data}
        description={t('settings.licence.description')}
      />
    </SettingSection>
  )
}

function ReleaseCheckSection() {
  const t = useT()
  const { data } = useQuery(updateQuery)
  const consent = useSetUpdateConsent()

  // Disabled (env switch, CI, dev build): offering it would promise a check
  // that cannot run.
  if (!data || data.disabled) {
    return null
  }

  const on = data.consent === 'on'

  return (
    <SettingSection title={t('settings.release.title')} on={on}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.release.body')}
      </p>
      {on && data.update_available && data.latest ? (
        <p className="text-[0.6875rem] text-muted">
          {t('settings.release.available', {
            version: data.latest.startsWith('v')
              ? data.latest
              : `v${data.latest}`,
          })}
        </p>
      ) : null}
      <ToggleButton
        title={t('settings.release.toggleTitle')}
        on={on}
        pending={consent.isPending}
        onChange={(enabled) => consent.mutate(enabled)}
      />
    </SettingSection>
  )
}
