import { useNavigate, useSearch } from '@tanstack/react-router'

import { AISettings } from '../components/ai-settings'
import { AppearanceSettings } from '../components/appearance-settings'
import { MCPSettings } from '../components/mcp-settings'
import { ModulesSettings } from '../components/modules-settings'
import { NotificationsSettings } from '../components/notifications-settings'
import { BandSummary } from '../components/page-band'
import { PoliciesSettings } from '../components/policies-settings'
import { Tabs, type TabItem } from '../components/ui/tabs'
import { useT } from '../lib/i18n'
import type { ConfigurationsTab } from '../lib/urls'

/**
 * ConfigurationsPage is Configuration (#139, #142, #143): the opt-in modules,
 * the policies, notifications, the local model, the MCP setup and the
 * appearance preferences. The URL owns the selected tab, so a reload or a
 * copied link lands on it.
 */
export function ConfigurationsPage() {
  const t = useT()
  const search = useSearch({ from: '/configurations' })
  const navigate = useNavigate()
  const tab: ConfigurationsTab = search.tab ?? 'modules'
  const configurationTabs: TabItem<ConfigurationsTab>[] = [
    { value: 'modules', label: t('settings.tabs.modules') },
    { value: 'policies', label: t('settings.tabs.policies') },
    { value: 'notifications', label: t('settings.tabs.notifications') },
    { value: 'ai', label: t('settings.tabs.ai') },
    { value: 'mcp', label: t('settings.tabs.mcp') },
    { value: 'appearance', label: t('settings.tabs.appearance') },
  ]

  return (
    <Tabs
      label={t('settings.tabs.aria')}
      items={configurationTabs}
      value={tab}
      onChange={(next) => {
        // replace: switching tabs is not a step the Back button should undo.
        void navigate({
          to: '/configurations',
          search: next === 'modules' ? {} : { tab: next },
          replace: true,
        })
      }}
      band={{
        summary: (
          <BandSummary
            title={t('nav.configurations')}
            subtitle={t('nav.configurations.subtitle')}
          />
        ),
      }}
    >
      {tab === 'policies' ? (
        <PoliciesSettings />
      ) : tab === 'notifications' ? (
        <NotificationsSettings />
      ) : tab === 'ai' ? (
        <AISettings />
      ) : tab === 'mcp' ? (
        <MCPSettings />
      ) : tab === 'appearance' ? (
        <AppearanceSettings />
      ) : (
        <ModulesSettings />
      )}
    </Tabs>
  )
}
