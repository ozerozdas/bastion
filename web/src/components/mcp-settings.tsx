import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { mcpQuery } from '../api/mcp'
import { useT } from '../lib/i18n'
import {
  buildMCPSnippet,
  mcpClients,
  type MCPClientId,
} from '../lib/mcp-setup'
import { SettingSection } from './setting-section'
import { Button } from './ui/button'

/** clientLocations names where each client keeps its MCP configuration. */
const clientLocations: Record<MCPClientId, string> = {
  'claude-code': 'settings.mcp.location.claude-code',
  'claude-desktop': 'settings.mcp.location.claude-desktop',
  codex: 'settings.mcp.location.codex',
  opencode: 'settings.mcp.location.opencode',
  vscode: 'settings.mcp.location.vscode',
  cursor: 'settings.mcp.location.cursor',
}

/**
 * MCPSettings is the Configuration modal's MCP tab (#163): what `bastion mcp`
 * exposes and a copy-ready setup snippet for each supported client. The
 * selected client is local state; it is not a stored preference.
 */
export function MCPSettings() {
  const t = useT()
  const { data } = useQuery(mcpQuery)
  const [client, setClient] = useState<MCPClientId>('claude-code')
  const [copied, setCopied] = useState(false)

  if (!data) {
    return null
  }

  const snippet = buildMCPSnippet(client, data)

  async function copy() {
    try {
      await navigator.clipboard.writeText(snippet)
      setCopied(true)
    } catch {
      // No clipboard (insecure context or a browser without the API): the
      // code block is still selectable, so copy is a no-op rather than an error.
      return
    }
  }

  return (
    <SettingSection title={t('settings.mcp.title')}>
      <p className="text-[0.6875rem] leading-relaxed text-muted">
        {t('settings.mcp.body')}
      </p>

      <label
        htmlFor="mcp-client"
        className="mt-1 text-[0.6875rem] text-muted"
      >
        {t('settings.mcp.client')}
      </label>
      <select
        id="mcp-client"
        aria-label={t('settings.mcp.client')}
        value={client}
        onChange={(event) => {
          setClient(event.target.value as MCPClientId)
          setCopied(false)
        }}
        className="h-8 w-full rounded-md border border-border-strong bg-surface px-2.5 text-[0.8125rem] text-fg"
      >
        {mcpClients.map((option) => (
          <option key={option.id} value={option.id}>
            {option.name}
          </option>
        ))}
      </select>

      <p className="mt-1 font-mono text-[0.625rem] text-faint">
        {t(clientLocations[client])}
      </p>
      <pre className="max-h-56 overflow-auto rounded-md border border-border-subtle bg-bg p-2 font-mono text-[0.625rem] leading-relaxed text-fg">
        {snippet}
      </pre>

      <div className="mt-1 flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="outline" onClick={copy}>
          {copied ? t('settings.mcp.copied') : t('settings.mcp.copy')}
        </Button>
        {client === 'opencode' ? (
          <p className="min-w-0 text-[0.625rem] leading-relaxed text-faint">
            {t('settings.mcp.opencodeNote')}
          </p>
        ) : null}
      </div>
    </SettingSection>
  )
}
