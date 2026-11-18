import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { epssQuery, useSetEPSSEnabled } from '../api/epss'
import { licencePolicyQuery } from '../api/licence-policy'
import { llmQuery, useSetLLMSettings } from '../api/llm'
import {
  notificationsQuery,
  useSetNotificationSettings,
  useTestNotification,
} from '../api/notifications'
import { eolQuery, useSetEOLEnabled } from '../api/eol'
import { FindingRulesEditor } from './finding-rules-editor'
import { outdatedQuery, useSetOutdatedEnabled } from '../api/outdated'
import { reachabilityQuery, useSetReachabilityEnabled } from '../api/reachability'
import { sastQuery, useSetSASTEnabled } from '../api/sast'
import { updateQuery, useSetUpdateConsent } from '../api/update'
import { formatNumber, useT } from '../lib/i18n'
import { AppearanceSettings } from './appearance-settings'
import { useDrawerFocus } from './drawer-focus'
import { LicencePolicyEditor } from './licence-policy-card'
import { MCPSettings } from './mcp-settings'
import { SettingSection } from './setting-section'
import { Button } from './ui/button'
import { Checkbox } from './ui/checkbox'
import { Tabs, type TabItem } from './ui/tabs'

type ConfigurationTab = 'modules' | 'notifications' | 'ai' | 'mcp' | 'appearance'

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
    { value: 'notifications', label: t('settings.tabs.notifications') },
    { value: 'ai', label: t('settings.tabs.ai') },
    { value: 'mcp', label: t('settings.tabs.mcp') },
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
          ) : tab === 'notifications' ? (
            <NotificationsSection />
          ) : tab === 'ai' ? (
            <AISection />
          ) : tab === 'mcp' ? (
            <MCPSettings />
          ) : (
            <div className="flex flex-col gap-3">
              <EPSSToggle />
              <ReachabilityToggle />
              <OutdatedToggle />
              <EOLToggle />
              <SASTToggle />
              <FindingRulesSection />
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

function EOLToggle() {
  const t = useT()
  const { data } = useQuery(eolQuery)
  const toggle = useSetEOLEnabled()

  if (!data) {
    return null
  }

  return (
    <SettingSection title={t('settings.eol.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.eol.body')}
      </p>
      <ToggleButton
        title={t('settings.eol.title')}
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

function NotificationsSection() {
  const t = useT()
  const { data } = useQuery(notificationsQuery)
  const save = useSetNotificationSettings()
  const test = useTestNotification()
  const [webhook, setWebhook] = useState('')
  const [feedback, setFeedback] = useState<'idle' | 'sent' | 'failed'>('idle')
  const [email, setEmail] = useState({
    host: '',
    port: '587',
    username: '',
    from: '',
    to: '',
  })
  const [password, setPassword] = useState('')

  // Seed the email form from the server; depend on the individual fields so
  // an unrelated save does not overwrite what the user is typing.
  useEffect(() => {
    if (!data) {
      return
    }
    setEmail({
      host: data.smtp_host,
      port: String(data.smtp_port),
      username: data.smtp_username,
      from: data.from,
      to: data.to,
    })
  }, [
    data?.smtp_host,
    data?.smtp_port,
    data?.smtp_username,
    data?.from,
    data?.to,
  ])

  if (!data) {
    return null
  }

  function saveWebhook() {
    const value = webhook.trim()
    if (value === '') {
      return
    }
    setFeedback('idle')
    save.mutate({ slack_webhook: value }, { onSuccess: () => setWebhook('') })
  }

  const emailReady =
    data.smtp_host !== '' && data.from !== '' && data.to !== ''
  const emailPort = Number(email.port)
  const emailPortValid =
    Number.isInteger(emailPort) && emailPort >= 1 && emailPort <= 65535

  function saveEmail() {
    const port = Number(email.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return
    }
    save.mutate({
      smtp_host: email.host.trim(),
      smtp_port: port,
      smtp_username: email.username.trim(),
      from: email.from.trim(),
      to: email.to.trim(),
    })
  }

  return (
    <SettingSection title={t('settings.notifications.title')} on={data.enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.notifications.body')}
      </p>

      <label
        htmlFor="notifications-threshold"
        className="mt-1 text-[0.6875rem] text-muted"
      >
        {t('settings.notifications.threshold')}
      </label>
      <select
        id="notifications-threshold"
        aria-label={t('settings.notifications.threshold')}
        value={data.threshold}
        onChange={(event) =>
          save.mutate({
            threshold: event.target.value as 'high' | 'critical',
          })
        }
        className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
      >
        <option value="high">
          {t('settings.notifications.threshold.high')}
        </option>
        <option value="critical">
          {t('settings.notifications.threshold.critical')}
        </option>
      </select>

      <label className="mt-1 flex items-center gap-2 text-[0.6875rem] text-muted">
        <Checkbox
          checked={data.slack_enabled}
          onChange={(event) =>
            save.mutate({ slack_enabled: event.target.checked })
          }
        />
        {t('settings.notifications.slack')}
      </label>

      <label
        htmlFor="notifications-webhook"
        className="mt-1 text-[0.6875rem] text-muted"
      >
        {t('settings.notifications.webhook')}
      </label>
      <p className="text-[0.6875rem] text-faint">
        {data.slack_configured
          ? t('settings.notifications.configured')
          : t('settings.notifications.notConfigured')}
      </p>
      <input
        id="notifications-webhook"
        type="password"
        autoComplete="off"
        value={webhook}
        placeholder={t('settings.notifications.webhookPlaceholder')}
        onChange={(event) => setWebhook(event.target.value)}
        className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
      />
      <div className="mt-1 flex flex-wrap gap-1.5">
        <Button
          type="button"
          size="sm"
          disabled={webhook.trim() === '' || save.isPending}
          onClick={saveWebhook}
        >
          {t('settings.notifications.save')}
        </Button>
        {data.slack_configured ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={save.isPending}
            onClick={() => save.mutate({ clear_slack_webhook: true })}
          >
            {t('settings.notifications.clear')}
          </Button>
        ) : null}
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={
            !(data.slack_configured || emailReady) || test.isPending
          }
          onClick={() => {
            setFeedback('idle')
            test.mutate(undefined, {
              onSuccess: () => setFeedback('sent'),
              onError: () => setFeedback('failed'),
            })
          }}
        >
          {test.isPending
            ? t('settings.notifications.testing')
            : t('settings.notifications.test')}
        </Button>
      </div>
      {feedback === 'sent' ? (
        <p className="text-[0.6875rem] text-muted">
          {t('settings.notifications.testSent')}
        </p>
      ) : feedback === 'failed' ? (
        <p className="text-[0.6875rem] text-critical">
          {t('settings.notifications.testFailed')}
        </p>
      ) : null}
      {save.isError ? (
        <p className="text-[0.6875rem] text-critical">
          {t('settings.notifications.saveFailed')}
        </p>
      ) : null}

      <div className="mt-2 border-t border-border-subtle pt-2">
        <label className="flex items-center gap-2 text-[0.6875rem] text-muted">
          <Checkbox
            checked={data.email_enabled}
            onChange={(event) =>
              save.mutate({ email_enabled: event.target.checked })
            }
          />
          {t('settings.notifications.email')}
        </label>
        <p className="mt-0.5 text-[0.6875rem] text-faint">
          {t('settings.notifications.emailHint')}
        </p>

        <div className="mt-1 flex gap-1.5">
          <div className="flex-1">
            <label
              htmlFor="notifications-email-host"
              className="text-[0.6875rem] text-muted"
            >
              {t('settings.notifications.emailHost')}
            </label>
            <input
              id="notifications-email-host"
              type="text"
              autoComplete="off"
              value={email.host}
              placeholder={t('settings.notifications.emailHostPlaceholder')}
              onChange={(event) =>
                setEmail({ ...email, host: event.target.value })
              }
              className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
            />
          </div>
          <div className="w-20">
            <label
              htmlFor="notifications-email-port"
              className="text-[0.6875rem] text-muted"
            >
              {t('settings.notifications.emailPort')}
            </label>
            <input
              id="notifications-email-port"
              type="number"
              min={1}
              max={65535}
              value={email.port}
              onChange={(event) =>
                setEmail({ ...email, port: event.target.value })
              }
              className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
            />
          </div>
        </div>

        <label
          htmlFor="notifications-email-username"
          className="mt-1 block text-[0.6875rem] text-muted"
        >
          {t('settings.notifications.emailUsername')}
        </label>
        <input
          id="notifications-email-username"
          type="text"
          autoComplete="off"
          value={email.username}
          onChange={(event) =>
            setEmail({ ...email, username: event.target.value })
          }
          className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
        />

        <label
          htmlFor="notifications-email-from"
          className="mt-1 block text-[0.6875rem] text-muted"
        >
          {t('settings.notifications.emailFrom')}
        </label>
        <input
          id="notifications-email-from"
          type="text"
          autoComplete="off"
          value={email.from}
          placeholder={t('settings.notifications.emailFromPlaceholder')}
          onChange={(event) =>
            setEmail({ ...email, from: event.target.value })
          }
          className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
        />

        <label
          htmlFor="notifications-email-to"
          className="mt-1 block text-[0.6875rem] text-muted"
        >
          {t('settings.notifications.emailTo')}
        </label>
        <input
          id="notifications-email-to"
          type="text"
          autoComplete="off"
          value={email.to}
          placeholder={t('settings.notifications.emailToPlaceholder')}
          onChange={(event) => setEmail({ ...email, to: event.target.value })}
          className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
        />

        <Button
          type="button"
          size="sm"
          className="mt-1"
          disabled={
            email.host.trim() === '' ||
            email.from.trim() === '' ||
            email.to.trim() === '' ||
            !emailPortValid ||
            save.isPending
          }
          onClick={saveEmail}
        >
          {t('settings.notifications.emailSave')}
        </Button>

        <label
          htmlFor="notifications-email-password"
          className="mt-2 block text-[0.6875rem] text-muted"
        >
          {t('settings.notifications.emailPassword')}
        </label>
        <p className="text-[0.6875rem] text-faint">
          {data.email_password_configured
            ? t('settings.notifications.configured')
            : t('settings.notifications.notConfigured')}
        </p>
        <input
          id="notifications-email-password"
          type="password"
          autoComplete="off"
          value={password}
          placeholder={t('settings.notifications.emailPasswordPlaceholder')}
          onChange={(event) => setPassword(event.target.value)}
          className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
        />
        <div className="mt-1 flex flex-wrap gap-1.5">
          <Button
            type="button"
            size="sm"
            disabled={password === '' || save.isPending}
            onClick={() => {
              setFeedback('idle')
              save.mutate(
                { email_password: password },
                { onSuccess: () => setPassword('') },
              )
            }}
          >
            {t('settings.notifications.emailSavePassword')}
          </Button>
          {data.email_password_configured ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={save.isPending}
              onClick={() => save.mutate({ clear_email_password: true })}
            >
              {t('settings.notifications.emailClear')}
            </Button>
          ) : null}
        </div>
      </div>

      <ToggleButton
        title={t('settings.notifications.title')}
        on={data.enabled}
        pending={save.isPending}
        onChange={(enabled) => save.mutate({ enabled })}
      />
    </SettingSection>
  )
}

function AISection() {
  const t = useT()
  const { data } = useQuery(llmQuery)
  const save = useSetLLMSettings()
  const [enabled, setEnabled] = useState(false)
  const [endpoint, setEndpoint] = useState('')
  const [model, setModel] = useState('')

  // Seed the form from the server; depend on the individual fields so an
  // unrelated save does not overwrite what the user is typing.
  useEffect(() => {
    if (!data) {
      return
    }
    setEnabled(data.enabled)
    setEndpoint(data.endpoint)
    setModel(data.model)
  }, [data?.enabled, data?.endpoint, data?.model])

  if (!data) {
    return null
  }

  const changed =
    enabled !== data.enabled ||
    endpoint.trim() !== data.endpoint ||
    model.trim() !== data.model

  return (
    <SettingSection title={t('settings.ai.title')} on={enabled}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.ai.body')}
      </p>

      <label className="mt-1 flex items-center gap-2 text-[0.6875rem] text-muted">
        <Checkbox
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
        />
        {t('settings.ai.enabled')}
      </label>

      <label
        htmlFor="ai-endpoint"
        className="mt-1 text-[0.6875rem] text-muted"
      >
        {t('settings.ai.endpoint')}
      </label>
      <input
        id="ai-endpoint"
        type="text"
        autoComplete="off"
        value={endpoint}
        placeholder={t('settings.ai.endpointPlaceholder')}
        onChange={(event) => setEndpoint(event.target.value)}
        className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
      />
      <p className="text-[0.6875rem] text-faint">
        {t('settings.ai.endpointHint')}
      </p>

      <label htmlFor="ai-model" className="mt-1 text-[0.6875rem] text-muted">
        {t('settings.ai.model')}
      </label>
      <input
        id="ai-model"
        type="text"
        autoComplete="off"
        value={model}
        placeholder={t('settings.ai.modelPlaceholder')}
        onChange={(event) => setModel(event.target.value)}
        className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint"
      />
      <p className="text-[0.6875rem] text-faint">
        {t('settings.ai.modelHint')}
      </p>

      <Button
        type="button"
        size="sm"
        className="mt-1 self-start"
        disabled={!changed || endpoint.trim() === '' || save.isPending}
        onClick={() =>
          save.mutate({
            enabled,
            endpoint: endpoint.trim(),
            model: model.trim(),
          })
        }
      >
        {save.isPending ? t('settings.ai.saving') : t('settings.ai.save')}
      </Button>
      {save.isError ? (
        <p className="text-[0.6875rem] text-critical">
          {save.error instanceof Error
            ? save.error.message
            : t('settings.ai.saveFailed')}
        </p>
      ) : null}
      {enabled && model.trim() === '' ? (
        <p className="text-[0.6875rem] text-critical">
          {t('settings.ai.modelRequired')}
        </p>
      ) : null}
    </SettingSection>
  )
}

function FindingRulesSection() {
  const t = useT()
  return (
    <SettingSection title={t('settings.rules.title')}>
      <FindingRulesEditor />
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
