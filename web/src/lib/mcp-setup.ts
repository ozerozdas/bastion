/**
 * Copy-ready MCP client configuration (#163).
 *
 * Every snippet starts `bastion mcp` with the binary and arguments GET
 * /api/mcp reports. JSON is pretty-printed with two spaces; TOML strings and
 * arrays use JSON's own escaping, which is valid TOML basic-string syntax.
 */

/** MCPCommand is the command and arguments GET /api/mcp returns. */
export type MCPCommand = { command: string; args: string[] }

/** MCPClientId names one supported MCP client. */
export type MCPClientId =
  | 'claude-code'
  | 'claude-desktop'
  | 'codex'
  | 'opencode'
  | 'vscode'
  | 'cursor'

/** MCPClient is one client's identifier and product name (never translated). */
export type MCPClient = { id: MCPClientId; name: string }

export const mcpClients: readonly MCPClient[] = [
  { id: 'claude-code', name: 'Claude Code' },
  { id: 'claude-desktop', name: 'Claude Desktop' },
  { id: 'codex', name: 'Codex' },
  { id: 'opencode', name: 'OpenCode' },
  { id: 'vscode', name: 'VS Code (Copilot)' },
  { id: 'cursor', name: 'Cursor' },
]

/** shellSafe characters need no quoting in a POSIX shell. */
const shellSafe = /^[A-Za-z0-9_@%+=:,./-]+$/

/** shellQuote wraps a token in single quotes unless it is plainly safe. */
export function shellQuote(value: string): string {
  if (shellSafe.test(value)) {
    return value
  }
  return `'${value.replaceAll("'", "'\\''")}'`
}

/** jsonSnippet is the shared { command, args } object, pretty-printed. */
function jsonSnippet(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

/** buildMCPSnippet renders the selected client's configuration text. */
export function buildMCPSnippet(
  client: MCPClientId,
  setup: MCPCommand,
): string {
  switch (client) {
    case 'claude-code':
      return [
        'claude mcp add bastion --',
        shellQuote(setup.command),
        ...setup.args.map(shellQuote),
      ].join(' ')
    case 'claude-desktop':
      return jsonSnippet({
        mcpServers: { bastion: { command: setup.command, args: setup.args } },
      })
    case 'codex':
      return [
        '[mcp_servers.bastion]',
        `command = ${JSON.stringify(setup.command)}`,
        `args = [${setup.args.map((arg) => JSON.stringify(arg)).join(', ')}]`,
      ].join('\n')
    case 'opencode':
      return jsonSnippet({
        $schema: 'https://opencode.ai/config.json',
        mcp: {
          servers: {
            bastion: {
              type: 'local',
              command: [setup.command, ...setup.args],
            },
          },
        },
      })
    case 'vscode':
      return jsonSnippet({
        servers: {
          bastion: { type: 'stdio', command: setup.command, args: setup.args },
        },
      })
    case 'cursor':
      return jsonSnippet({
        mcpServers: { bastion: { command: setup.command, args: setup.args } },
      })
  }
}
