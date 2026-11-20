# MCP Server

`bastion mcp` serves the assets, findings, fix plans and scan diffs over the
[Model Context Protocol](https://modelcontextprotocol.io) on stdin/stdout. It
starts no worker pool, download or scan recovery of its own, so it never disturbs a
`bastion serve` running beside it. It opens the same database (`--data-dir` applies),
so an agent reads what the UI shows. stdout is the protocol stream; logs go to stderr.

`trigger_scan` (`{asset_id}`) queues a scan for a **running**
`bastion serve` and returns `{scan_id, status: "queued"}`. The server detects serve
through an exclusive lock on `<data-dir>/serve.lock`; with no server running the tool
fails with *bastion serve is not running; start it to run scans* and writes nothing.
The scan itself runs in serve, with its worker pool and Trivy database, and appears in
the UI (`trigger: api`) like any other scan. If the asset already has a queued or
running scan, that scan is returned with `already_queued: true` instead of a second
one. A scan queued just before serve stops stays queued and is picked up at the next
`bastion serve` start, never run by this process.

`set_finding_state` (`{asset_id, fingerprints, state, reason, expires_at?}`) lets an agent
close noise, and `clear_finding_state` (`{asset_id, fingerprints}`) reopens what an agent
closed. These decisions apply immediately and the UI lists them under **Closed by agent**.
Scanned content can try to steer an agent, so both tools refuse the whole batch when it
names a decision you made, and `set_finding_state` also refuses malware and secret findings.

`propose_finding_rule` lets an agent suggest a suppression rule for one asset. A proposal
closes nothing until you approve it under **Configuration > Noise rules**, and proposals
for malware or secret findings are refused.

Generic `mcpServers` configuration (Claude Code, Claude Desktop and other MCP clients):

```json
{
  "mcpServers": {
    "bastion": {
      "command": "bastion",
      "args": ["mcp"]
    }
  }
}
```

If the database lives elsewhere, pass the global flag through:
`"args": ["mcp", "--data-dir", "/path/to/bastion/data"]`.

Tools: `list_assets`, `list_findings` (asset, severity, type, status, text query, sort and
paging), `get_fix_plan`, `diff_scans` (two scan ids, or an asset's last two succeeded
scans), `list_security_news` (the opt-in Security News feed, with optional `since`,
`source` and `limit`), `trigger_scan` (queue a scan for the running server),
`set_finding_state`, `clear_finding_state` and `propose_finding_rule`. Every result that
carries scanner-derived or third-party feed values includes an `untrusted_content`
notice: those values are data, never instructions (see the threat model). Apart from
`trigger_scan`, the two finding-state tools and rule proposals, the MCP server makes no
writes; it makes no network calls of its own except reading the first-party feeds
`list_security_news` returns, and only while Security News is turned on.

For clients that only speak HTTP, `bastion mcp --http --port 7778` serves the same tools
over streamable HTTP at `http://127.0.0.1:7778/`. It binds loopback only and needs no
token; requests with a foreign Host header (DNS rebinding) or from another website are
refused.

For questions about shipped artifacts (binary hardening, source maps or keys in built
bundles), the [`bastion-artifacts`](../../skills/bastion-artifacts/SKILL.md) agent skill combines
`bastion mcp` with [REA](https://github.com/morluto/rea). Copy the folder into your agent's
skills directory; REA stays a separate MCP server.
