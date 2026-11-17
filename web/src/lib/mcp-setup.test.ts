import { describe, expect, it } from 'vitest'

import { buildMCPSnippet, shellQuote } from './mcp-setup'

const setup = {
  command: "/Applications/My Tools/bastion's",
  args: ['mcp', '--data-dir', '/home/me/My Data'],
}

describe('shellQuote', () => {
  it('leaves plain paths alone', () => {
    expect(shellQuote('/usr/local/bin/bastion')).toBe('/usr/local/bin/bastion')
  })

  it('quotes spaces and escapes single quotes', () => {
    expect(shellQuote('/My Tools/bastion')).toBe("'/My Tools/bastion'")
    expect(shellQuote("bastion's")).toBe("'bastion'\\''s'")
  })
})

describe('buildMCPSnippet', () => {
  it('renders the Claude Code command with shell-quoted arguments', () => {
    expect(buildMCPSnippet('claude-code', setup)).toBe(
      "claude mcp add bastion -- '/Applications/My Tools/bastion'\\''s' mcp --data-dir '/home/me/My Data'",
    )
  })

  it('renders Claude Desktop as JSON that round-trips the command', () => {
    const snippet = buildMCPSnippet('claude-desktop', setup)
    expect(JSON.parse(snippet)).toEqual({
      mcpServers: {
        bastion: { command: setup.command, args: setup.args },
      },
    })
    expect(snippet).toContain('\n  "mcpServers"')
  })

  it('escapes TOML strings with JSON escaping', () => {
    const snippet = buildMCPSnippet('codex', setup)
    expect(snippet).toBe(
      [
        '[mcp_servers.bastion]',
        `command = ${JSON.stringify(setup.command)}`,
        'args = ["mcp", "--data-dir", "/home/me/My Data"]',
      ].join('\n'),
    )
  })

  it('renders OpenCode with the local server command array', () => {
    expect(JSON.parse(buildMCPSnippet('opencode', setup))).toEqual({
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
  })

  it('renders VS Code as a stdio server', () => {
    expect(JSON.parse(buildMCPSnippet('vscode', setup))).toEqual({
      servers: {
        bastion: { type: 'stdio', command: setup.command, args: setup.args },
      },
    })
  })

  it('renders Cursor like Claude Desktop', () => {
    expect(JSON.parse(buildMCPSnippet('cursor', setup))).toEqual({
      mcpServers: {
        bastion: { command: setup.command, args: setup.args },
      },
    })
  })
})
