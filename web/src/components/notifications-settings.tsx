import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import {
  notificationsQuery,
  useSetNotificationSettings,
  useTestNotification,
} from '../api/notifications'
import { useT } from '../lib/i18n'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Checkbox } from './ui/checkbox'
import { InfoTip } from './ui/info-tip'
import { Switch } from './ui/switch'

const inputClass =
  'h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg placeholder:text-faint'
const labelClass = 'text-xs font-medium text-muted'

/**
 * NotificationsSettings is Configuration's Notifications tab: the scan
 * threshold, the Slack webhook and the SMTP details. The webhook and password
 * are write-only, so the server reports only whether they are configured.
 */
export function NotificationsSettings() {
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

  const emailReady = data.smtp_host !== '' && data.from !== '' && data.to !== ''
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
    <section
      aria-label={t('settings.notifications.title')}
      className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-2">
        <h2 className="text-[0.9375rem] font-semibold">
          {t('settings.notifications.title')}
        </h2>
        <Badge tone={data.enabled ? 'ok' : 'neutral'}>
          {data.enabled ? t('settings.badge.on') : t('settings.badge.off')}
        </Badge>
        <InfoTip
          label={t('settings.module.about', {
            title: t('settings.notifications.title'),
          })}
          content={t('settings.notifications.body')}
        />
        <div className="-my-1 -mr-1 ml-auto">
          <Switch
            label={t('settings.notifications.title')}
            checked={data.enabled}
            disabled={save.isPending}
            onCheckedChange={(enabled) => save.mutate({ enabled })}
          />
        </div>
      </div>

      <div className="flex max-w-sm flex-col gap-1">
        <label htmlFor="notifications-threshold" className={labelClass}>
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
      </div>

      <div className="flex flex-col gap-2 border-t border-border-subtle pt-3">
        <label className="flex items-center gap-2 text-xs font-semibold text-fg">
          <Checkbox
            checked={data.slack_enabled}
            onChange={(event) =>
              save.mutate({ slack_enabled: event.target.checked })
            }
          />
          {t('settings.notifications.slack')}
        </label>

        {data.slack_enabled ? (
          <>
            <div className="flex flex-col gap-1">
              <label htmlFor="notifications-webhook" className={labelClass}>
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
                className={inputClass}
              />
            </div>

            <div className="flex flex-wrap items-center justify-end gap-1.5">
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
          </>
        ) : null}
        {save.isError ? (
          <p className="text-[0.6875rem] text-critical">
            {t('settings.notifications.saveFailed')}
          </p>
        ) : null}
      </div>

      <div className="flex flex-col gap-2 border-t border-border-subtle pt-3">
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-xs font-semibold text-fg">
            <Checkbox
              checked={data.email_enabled}
              onChange={(event) =>
                save.mutate({ email_enabled: event.target.checked })
              }
            />
            {t('settings.notifications.email')}
          </label>
          <InfoTip
            label={t('settings.module.about', {
              title: t('settings.notifications.email'),
            })}
            content={t('settings.notifications.emailHint')}
          />
        </div>

        {data.email_enabled ? (
          <>
            <div className="flex flex-col gap-1">
              <label htmlFor="notifications-email-host" className={labelClass}>
                {t('settings.notifications.emailHost')}
              </label>
              <div className="flex gap-1.5">
                <input
                  id="notifications-email-host"
                  type="text"
                  autoComplete="off"
                  value={email.host}
                  placeholder={t('settings.notifications.emailHostPlaceholder')}
                  onChange={(event) =>
                    setEmail({ ...email, host: event.target.value })
                  }
                  className={inputClass}
                />
                <div className="w-20 shrink-0">
                  <input
                    id="notifications-email-port"
                    aria-label={t('settings.notifications.emailPort')}
                    type="number"
                    min={1}
                    max={65535}
                    value={email.port}
                    onChange={(event) =>
                      setEmail({ ...email, port: event.target.value })
                    }
                    className={inputClass}
                  />
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <label
                htmlFor="notifications-email-username"
                className={labelClass}
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
                className={inputClass}
              />
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <label
                  htmlFor="notifications-email-from"
                  className={labelClass}
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
                  className={inputClass}
                />
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor="notifications-email-to" className={labelClass}>
                  {t('settings.notifications.emailTo')}
                </label>
                <input
                  id="notifications-email-to"
                  type="text"
                  autoComplete="off"
                  value={email.to}
                  placeholder={t('settings.notifications.emailToPlaceholder')}
                  onChange={(event) =>
                    setEmail({ ...email, to: event.target.value })
                  }
                  className={inputClass}
                />
              </div>
            </div>

            <div className="flex justify-end">
              <Button
                type="button"
                size="sm"
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
            </div>

            <div className="flex flex-col gap-1">
              <label
                htmlFor="notifications-email-password"
                className={labelClass}
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
                placeholder={t(
                  'settings.notifications.emailPasswordPlaceholder',
                )}
                onChange={(event) => setPassword(event.target.value)}
                className={inputClass}
              />
            </div>

            <div className="flex flex-wrap items-center justify-end gap-1.5">
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
          </>
        ) : null}
      </div>
    </section>
  )
}
