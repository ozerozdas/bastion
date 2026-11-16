import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { epssQuery, useSetEPSSEnabled } from '../api/epss'
import { licencePolicyQuery } from '../api/licence-policy'
import { outdatedQuery, useSetOutdatedEnabled } from '../api/outdated'
import { reachabilityQuery, useSetReachabilityEnabled } from '../api/reachability'
import { sastQuery, useSetSASTEnabled } from '../api/sast'
import { updateQuery, useSetUpdateConsent } from '../api/update'
import { AppearanceSettings } from './appearance-settings'
import { useDrawerFocus } from './drawer-focus'
import { LicencePolicyEditor } from './licence-policy-card'
import { SettingSection } from './setting-section'
import { Button } from './ui/button'
import { Tabs, type TabItem } from './ui/tabs'

type ConfigurationTab = 'modules' | 'appearance'

const configurationTabs: TabItem<ConfigurationTab>[] = [
  { value: 'modules', label: 'Modules' },
  { value: 'appearance', label: 'Appearance' },
]

/**
 * SettingsDialog is the Configuration modal (#139, #142): the opt-in modules
 * and the global policy that used to be sidebar cards, plus the appearance
 * preferences. Each module says what it does and what it downloads before the
 * user turns it on, and separates the state (a badge) from the action (a
 * button).
 */
export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const { panel, onKeyDown } = useDrawerFocus(onClose)
  const [tab, setTab] = useState<ConfigurationTab>('modules')

  return (
    <div className="fixed inset-0 z-40">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="absolute inset-0 bg-black/20"
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
              Configuration
            </h2>
            <p className="text-xs text-muted">
              Modules, policies and appearance. Modules are off until you turn
              them on.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="ml-auto shrink-0"
            onClick={onClose}
          >
            Close
          </Button>
        </div>

        <Tabs
          label="Configuration sections"
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
  return (
    <Button
      type="button"
      size="sm"
      variant={on ? 'outline' : 'default'}
      className="mt-0.5 self-start"
      aria-label={`Turn ${on ? 'off' : 'on'} ${title}`}
      disabled={pending}
      onClick={() => onChange(!on)}
    >
      {on ? 'Turn off' : 'Turn on'}
    </Button>
  )
}

function EPSSToggle() {
  const { data } = useQuery(epssQuery)
  const toggle = useSetEPSSEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title="EPSS exploit scores" on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        At most once a day, downloads the FIRST.org EPSS feed — a ~2.8 MB gzipped
        CSV from epss.empiricalsecurity.com — to rank findings by how likely each
        CVE is to be exploited. Nothing is uploaded.
      </p>
      {data.enabled ? (
        data.error ? (
          <>
            <p className="text-[0.6875rem] text-critical">Download failed</p>
            <p
              className="min-w-0 truncate font-mono text-[0.625rem] text-muted"
              title={data.error}
            >
              {data.error}
            </p>
            <p className="text-[0.6875rem] text-faint">Retries daily.</p>
          </>
        ) : data.count === undefined ? (
          <p className="font-mono text-[0.6875rem] text-muted">Downloading scores…</p>
        ) : (
          <p className="text-[0.6875rem] text-muted">
            <span className="tabular-nums">{data.count.toLocaleString()}</span>{' '}
            CVEs
            {data.score_date ? ` · ${data.score_date.slice(0, 10)}` : ''}
          </p>
        )
      ) : null}
      <ToggleButton
        title="EPSS exploit scores"
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function ReachabilityToggle() {
  const { data } = useQuery(reachabilityQuery)
  const toggle = useSetReachabilityEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title="Go reachability" on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        Runs govulncheck on Go repositories to tell whether vulnerable code is
        actually called, not just present. Uses vuln.go.dev for advisories and
        proxy.golang.org (or your GOPROXY) for module downloads; nothing about
        the scan is uploaded.
      </p>
      {data.enabled ? (
        data.available ? (
          <p className="text-[0.6875rem] text-muted">govulncheck runs on Go scans.</p>
        ) : (
          <>
            <p className="text-[0.6875rem] text-critical">No Go toolchain</p>
            <p className="text-[0.6875rem] text-faint">
              Install Go; findings stay unknown until then.
            </p>
          </>
        )
      ) : null}
      <ToggleButton
        title="Go reachability"
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function OutdatedToggle() {
  const { data } = useQuery(outdatedQuery)
  const toggle = useSetOutdatedEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title="Outdated packages" on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        Looks up the latest version of each package on deps.dev (api.deps.dev)
        during scans. Only ecosystems, package names and versions are sent.
      </p>
      <ToggleButton
        title="Outdated packages"
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function SASTToggle() {
  const { data } = useQuery(sastQuery)
  const toggle = useSetSASTEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title="SAST" on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        Downloads Opengrep {data.version} (~47 MB) and the community rules
        (~1.1 MB) from GitHub, then scans repository source locally for code
        issues. Both downloads are checksum-verified.
      </p>
      {data.enabled ? (
        data.installing ? (
          <p className="font-mono text-[0.6875rem] text-muted">
            Downloading Opengrep {data.version}…
          </p>
        ) : data.install_error ? (
          <>
            <p className="text-[0.6875rem] text-critical">Download failed</p>
            <p
              className="min-w-0 truncate font-mono text-[0.625rem] text-muted"
              title={data.install_error}
            >
              {data.install_error}
            </p>
          </>
        ) : data.state === 'installed' ? (
          <p className="text-[0.6875rem] text-muted">
            Opengrep {data.version} runs on repository scans.
          </p>
        ) : (
          <p className="text-[0.6875rem] text-muted">
            Not installed yet; the next scan downloads it.
          </p>
        )
      ) : null}
      <ToggleButton
        title="SAST"
        on={data.enabled}
        pending={toggle.isPending}
        onChange={(enabled) => toggle.mutate(enabled)}
      />
    </SettingSection>
  )
}

function LicencePolicySection() {
  const { data } = useQuery(licencePolicyQuery())

  if (!data) {
    return null
  }

  return (
    <SettingSection title="Licence policy">
      <LicencePolicyEditor
        policy={data}
        description="The policy for every project. An allowed licence is hidden; a denied one stays visible at high severity. Matching is exact, so “MIT OR Apache-2.0” is its own entry."
      />
    </SettingSection>
  )
}

function ReleaseCheckSection() {
  const { data } = useQuery(updateQuery)
  const consent = useSetUpdateConsent()

  // Disabled (env switch, CI, dev build): offering it would promise a check
  // that cannot run.
  if (!data || data.disabled) {
    return null
  }

  const on = data.consent === 'on'

  return (
    <SettingSection title="Release check" on={on}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        At most once a day, asks github.com for the newest bastion release tag.
        Sends your IP and User-Agent; nothing else leaves your machine.
      </p>
      {on && data.update_available && data.latest ? (
        <p className="text-[0.6875rem] text-muted">
          {data.latest.startsWith('v') ? data.latest : `v${data.latest}`} is
          available; the sidebar shows the upgrade command.
        </p>
      ) : null}
      <ToggleButton
        title="release check"
        on={on}
        pending={consent.isPending}
        onChange={(enabled) => consent.mutate(enabled)}
      />
    </SettingSection>
  )
}
