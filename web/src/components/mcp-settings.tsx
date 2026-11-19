import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { mcpQuery } from '../api/mcp'
import { useT } from '../lib/i18n'
import {
  buildMCPSnippet,
  mcpClients,
  type MCPClientId,
} from '../lib/mcp-setup'
import { Button } from './ui/button'
import { InfoTip } from './ui/info-tip'

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
 * MCPSettings is Configuration's MCP tab (#163): what `bastion mcp` exposes
 * and a copy-ready setup snippet for each supported client. The selected
 * client is local state; it is not a stored preference.
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
    <section
      aria-label={t('settings.mcp.title')}
      className="flex w-full max-w-2xl flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
    >
      <div className="flex items-center gap-2">
        <h2 className="text-[0.9375rem] font-semibold">
          {t('settings.mcp.title')}
        </h2>
        <InfoTip
          label={t('settings.module.about', {
            title: t('settings.mcp.title'),
          })}
          content={t('settings.mcp.body')}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="mcp-client" className="text-xs font-medium text-muted">
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
      </div>

      <p className="font-mono text-[0.625rem] text-faint">
        {t(clientLocations[client])}
      </p>
      <pre className="max-h-56 overflow-auto rounded-md border border-border-subtle bg-bg p-2 font-mono text-[0.625rem] leading-relaxed text-fg">
        {snippet}
      </pre>

      <div className="flex flex-wrap items-center justify-end gap-2">
        {client === 'opencode' ? (
          <p className="min-w-0 text-[0.625rem] leading-relaxed text-faint">
            {t('settings.mcp.opencodeNote')}
          </p>
        ) : null}
        <Button type="button" variant="outline" onClick={copy}>
          {copied ? t('settings.mcp.copied') : t('settings.mcp.copy')}
        </Button>
      </div>
    </section>
  )
}
