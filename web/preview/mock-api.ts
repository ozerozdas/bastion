// A dev-only stand-in for the Go server, so the UI can be tuned with hot reload
// and no session. Nothing here reaches the production bundle: only
// vite.preview.config.ts imports it. State lives in memory, is shared by every
// open browser and resets when the preview restarts.
import type { Plugin } from 'vite'

import type { components } from '../src/api/schema'

type S = components['schemas']
type Finding = S['Finding']
type Asset = S['Asset']
type Scan = S['Scan']
type Totals = S['SeverityTotals']

// ponytail: local shapes, because the web package has no @types/node.
type Req = {
  url?: string
  method?: string
  on(event: string, listener: (chunk?: unknown) => void): void
}
type Res = {
  statusCode: number
  setHeader(name: string, value: string): void
  write(body: string): void
  end(body?: string): void
}

const start = Date.now()
const ago = (hours: number) => new Date(start - hours * 3_600_000).toISOString()
const zero = (): Totals => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 })
const severityRank: S['Severity'][] = ['critical', 'high', 'medium', 'low', 'unknown']

function link(id: number, ref: string, source: S['AssetLinkSource']): S['AssetLink'] {
  return { asset_id: id, ref, display_name: ref, source }
}

function asset(id: number, kind: S['AssetKind'], ref: string, extra: Partial<Asset> = {}): Asset {
  return {
    id,
    kind,
    display_name: ref,
    ref,
    created_at: ago(24 * 40),
    scan_schedule: 'off',
    open_counts: zero(),
    linked_images: [],
    ...extra,
  }
}

const longName =
  'acme-enterprise-platform/customer-identity-and-access-management-gateway-service-with-a-very-long-name'

const assets: Asset[] = [
  asset(1, 'repo', 'acme/payments-api', {
    default_branch: 'main',
    connection_id: 1,
    scan_schedule: 'daily',
    linked_images: [link(4, 'ghcr.io/acme/payments-api:1.42.0', 'oci')],
  }),
  asset(2, 'repo', 'acme/web-storefront', { default_branch: 'develop', connection_id: 1, scan_schedule: 'weekly' }),
  asset(3, 'path', '/Users/dev/projects/internal-tools'),
  asset(4, 'image', 'ghcr.io/acme/payments-api:1.42.0', { linked_repo: link(1, 'acme/payments-api', 'oci') }),
  asset(5, 'image', '123456789012.dkr.ecr.eu-west-1.amazonaws.com/orders:2026.11.3', {
    connection_id: 2,
    ecr_registry: '123456789012.dkr.ecr.eu-west-1.amazonaws.com',
  }),
  asset(6, 'repo', 'acme/never-scanned-service', { default_branch: 'main', connection_id: 1 }),
  asset(7, 'repo', 'acme/legacy-billing', { default_branch: 'master', connection_id: 1 }),
  asset(8, 'repo', 'acme/clean-library', { default_branch: 'main', connection_id: 1 }),
  asset(9, 'repo', longName, { default_branch: 'release/2026-q4-long-lived-branch', connection_id: 1 }),
]

// Every scanned asset gets four scans; the newest id is assetId * 10 + 3.
const scans: Scan[] = assets
  .filter((item) => item.id !== 6)
  .flatMap((item) =>
    [0, 1, 2, 3].map((step): Scan => {
      const failed = item.id === 7 && step === 3
      return {
        id: item.id * 10 + step,
        asset_id: item.id,
        target_ref: item.ref,
        status: failed ? 'failed' : 'succeeded',
        trigger: step % 2 ? 'ui' : 'api',
        started_at: ago((3 - step) * 26 + item.id + 0.1),
        finished_at: ago((3 - step) * 26 + item.id),
        counts: zero(),
        ...(failed ? { error: 'fetch: repository not found or the token cannot read it' } : {}),
        scanner_runs: [
          { scanner: 'trivy', scanner_version: '0.68.1', db_version: '2026-11-18', status: 'succeeded', duration_ms: 18_420 },
          { scanner: 'gitleaks', scanner_version: '8.28.0', status: failed ? 'failed' : 'succeeded', duration_ms: 2_310 },
          { scanner: 'osv', status: 'succeeded', duration_ms: 940, warning: 'one lockfile could not be parsed' },
        ],
      }
    }),
  )

const packages = ['lodash', 'express', 'golang.org/x/net', 'openssl', 'axios', 'jsonwebtoken', 'pillow', 'log4j-core', 'minimist', 'next']
const locations = [
  'package-lock.json',
  'go.mod',
  'src/services/payments/internal/gateway/handlers/checkout.ts',
  'tests/fixtures/sample.env',
  'deploy/k8s/deployment.yaml',
  'Dockerfile',
  'internal/auth/token_test.go',
  'apps/storefront/src/features/checkout/components/payment-form/validators/card-number-validator.spec.ts',
]
const titles: Record<S['FindingType'], string[]> = {
  vulnerability: [
    'Prototype pollution in merge helper',
    'HTTP/2 rapid reset allows denial of service',
    'Improper validation of certificate chains when a custom verifier is combined with session resumption across renegotiated connections',
  ],
  secret: ['AWS access key committed to the repository', 'Generic API key in configuration'],
  outdated: ['Package is two major versions behind', 'Newer patch release available'],
  misconfig: ['Container runs as root', 'Deployment has no resource limits'],
  license: ['AGPL-3.0 dependency is denied by policy', 'Unknown licence on a direct dependency'],
  malware: ['Package publishes a credential stealer'],
  sast: ['SQL query built from request input', 'Weak hash used for passwords'],
}
const types = Object.keys(titles) as S['FindingType'][]
const findingAssets = [1, 1, 2, 2, 3, 4, 5, 7, 9]

const findings: Finding[] = Array.from({ length: 160 }, (_, i) => {
  const type = i % 37 === 36 ? 'malware' : types.filter((kind) => kind !== 'malware')[i % 6]
  const assetId = findingAssets[i % findingAssets.length]
  const hasPackage = type !== 'secret' && type !== 'misconfig' && type !== 'sast'
  const options = titles[type]
  const row: Finding = {
    id: i + 1,
    asset_id: assetId,
    scan_id: assetId === 7 ? 72 : assetId * 10 + 3,
    fingerprint: `fp-${String(i + 1).padStart(4, '0')}`,
    type,
    severity: severityRank[(i * 3 + (i % 4)) % 5],
    title: options[i % options.length],
    rule_id: type === 'vulnerability' ? `CVE-2026-${String(1000 + (i % 24))}` : `${type.toUpperCase()}-${String(i % 9).padStart(3, '0')}`,
    location: locations[i % locations.length],
    occurrences: i % 7 === 0 ? 4 : 1,
    scanner: i % 3 ? 'trivy' : 'osv',
    scanners: i % 5 === 0 ? ['trivy', 'osv'] : ['trivy'],
    status: 'open',
    first_seen_scan_id: assetId * 10 + (i % 3),
    references: i % 4 === 3 ? [] : ['https://example.com/advisories/preview', 'https://example.org/a/very/long/reference/path/that/must/wrap/inside/the/drawer/without/overflowing'],
    ...(i % 6 === 5 ? {} : { description: 'An attacker who controls the input can trigger this condition. '.repeat((i % 4) + 1).trim() }),
    ...(hasPackage
      ? { package_name: packages[i % packages.length], package_version: `${(i % 5) + 1}.${i % 12}.0`, ecosystem: i % 2 ? 'npm' : 'go' }
      : {}),
    ...(hasPackage && i % 3 !== 0 ? { fixed_version: `${(i % 5) + 2}.0.1` } : {}),
    ...(type === 'vulnerability' ? { epss: { score: ((i * 7) % 100) / 100, percentile: ((i * 11) % 100) / 100 } } : {}),
    ...(type === 'vulnerability' ? { reachability: (['reachable', 'unreachable', 'unknown'] as const)[i % 3] } : {}),
    ...(type === 'license' ? { licence_policy: 'deny' as const } : {}),
  }
  if (type === 'malware' || type === 'secret') return row
  if (i % 17 === 0) Object.assign(row, { status: 'ignored', state: 'false_positive', reason: 'Only reachable from test code.', decided_by: 'user' })
  else if (i % 19 === 0) Object.assign(row, { status: 'ignored', state: 'ignored', reason: 'Build tooling, never shipped to production.', decided_by: 'agent' })
  else if (i % 23 === 0) Object.assign(row, { status: 'ignored', state: 'accepted_risk', reason: 'Fixtures are not deployed', decided_by: 'user', rule_ref: 1 })
  else if (i % 29 === 0) Object.assign(row, { state: 'accepted_risk', reason: 'Waiting for the vendor patch.', decided_by: 'user', expires_at: ago(48), expired: true })
  return row
})

const rules: S['FindingRule'][] = [
  { id: 3, asset_id: 2, path_glob: 'apps/*/stories/*', state: 'false_positive', reason: 'Storybook examples are never deployed.', status: 'proposed', created_by: 'agent', created_at: ago(3), matched: 0 },
  { id: 2, finding_type: 'outdated', state: 'ignored', reason: 'Upgrades are handled by the weekly dependency PR.', expires_at: ago(-24 * 30), status: 'active', created_by: 'user', created_at: ago(24 * 6), matched: 0 },
  { id: 1, path_glob: 'tests/*', state: 'accepted_risk', reason: 'Fixtures are not deployed', status: 'active', created_by: 'user', created_at: ago(24 * 12), matched: 0 },
]

const connections: S['Connection'][] = [
  { id: 1, kind: 'github', name: 'Acme GitHub', status: 'ok', login: 'acme-bot', ecr_asset_count: 0, last_checked_at: ago(1), created_at: ago(24 * 40) },
  { id: 2, kind: 'aws', name: 'Production AWS', status: 'error', profile: 'prod', region: 'eu-west-1', account: '123456789012', arn: 'arn:aws:iam::123456789012:role/bastion-readonly', ecr_asset_count: 1, hint: 'The SSO session expired. Run aws sso login --profile prod.', last_checked_at: ago(5), created_at: ago(24 * 20) },
  { id: 3, kind: 'docker', name: 'Local Docker', status: 'ok', ecr_asset_count: 0, created_at: ago(24 * 40) },
]

// Settings endpoints: GET returns the object and PUT merges the request into it.
const settings: Record<string, Record<string, unknown>> = {
  epss: { enabled: true, last_refresh: ago(6), score_date: ago(20).slice(0, 10), count: 298_114 },
  outdated: { enabled: true },
  eol: { enabled: true },
  reachability: { enabled: true, available: true },
  sast: { enabled: true, state: 'installed', version: '1.11.0', installing: false },
  llm: { enabled: true, endpoint: 'http://127.0.0.1:11434/v1', model: 'qwen3:14b' },
  'licence-policy': { allow: ['MIT', 'Apache-2.0', 'BSD-3-Clause'], deny: ['AGPL-3.0', 'SSPL-1.0'] },
  preferences: {},
  notifications: {
    enabled: true, threshold: 'high', slack_enabled: true, slack_configured: true, email_enabled: false,
    smtp_host: 'smtp.example.com', smtp_port: 587, smtp_username: 'alerts', from: 'alerts@example.com',
    to: 'security@example.com', email_password_configured: true,
  },
}

let trivy: S['TrivyDBStatus'] = { state: 'ready', updated_at: ago(4) }
let consent: S['UpdateConsent'] = 'on'
let nextScanId = 1000
let nextId = 100
const clients = new Set<Res>()
const timers = new Map<number, ReturnType<typeof setTimeout>[]>()

const hidden = (f: Finding) => f.status === 'ignored' && !f.expired
const isTestPath = (path = '') => /(^|\/)(tests?|__tests__|testdata|fixtures|spec|mocks)\/|_test\.|\.(test|spec)\./.test(path)
const isIndirect = (f: Finding) => f.id % 2 === 0

function countOpen(rows: Finding[]): Totals {
  const totals = zero()
  for (const row of rows) if (!hidden(row)) totals[row.severity] += 1
  return totals
}

function assetView(item: Asset): Asset {
  const latest = scans.filter((scan) => scan.asset_id === item.id).at(-1)
  return {
    ...item,
    open_counts: countOpen(findings.filter((f) => f.asset_id === item.id)),
    ...(latest ? { last_scan: { scan_id: latest.id, status: latest.status, finished_at: latest.finished_at } } : {}),
  }
}

function ruleView(rule: S['FindingRule']): S['FindingRule'] {
  return { ...rule, matched: findings.filter((f) => f.rule_ref === rule.id && hidden(f)).length }
}

function filtered(query: URLSearchParams): Finding[] {
  const q = query.get('q')?.toLowerCase()
  const live = new Set(assets.map((item) => item.id))
  const rows = findings.filter((f) => {
    if (!live.has(f.asset_id)) return false
    if (query.has('asset_id') && f.asset_id !== Number(query.get('asset_id'))) return false
    if (query.has('type') && f.type !== query.get('type')) return false
    if (query.has('severity') && f.severity !== query.get('severity')) return false
    if (query.has('decided_by') && (f.decided_by !== query.get('decided_by') || !hidden(f))) return false
    const status = query.get('status') ?? (query.has('decided_by') ? 'ignored' : 'open')
    if (status === 'open' && hidden(f)) return false
    if (status === 'ignored' && !hidden(f)) return false
    if (query.get('fix') === 'available' && !f.fixed_version) return false
    if (query.get('fix') === 'none' && f.fixed_version) return false
    if (query.get('dependency') === 'direct' && (!f.package_name || isIndirect(f))) return false
    if (query.get('dependency') === 'indirect' && (!f.package_name || !isIndirect(f))) return false
    if (query.get('hide_tests') === 'true' && isTestPath(f.location)) return false
    if (query.get('hide_maintenance') === 'true' && (f.type === 'license' || f.type === 'outdated')) return false
    return !q || `${f.title} ${f.rule_id} ${f.package_name} ${f.location}`.toLowerCase().includes(q)
  })
  const sort = query.get('sort') ?? 'severity'
  const direction = query.get('order') === 'desc' ? -1 : 1
  const value = (f: Finding) =>
    sort === 'severity' ? String(severityRank.indexOf(f.severity)) : String(f[sort as keyof Finding] ?? '')
  return rows.sort((a, b) => direction * value(a).localeCompare(value(b)) || a.id - b.id)
}

function groupFindings(rows: Finding[]): S['FindingGroup'][] {
  const groups = new Map<string, Finding[]>()
  for (const row of rows) {
    const key = `${row.rule_id ?? row.fingerprint}:${row.type}`
    groups.set(key, [...(groups.get(key) ?? []), row])
  }
  return [...groups].map(([key, members]) => {
    const fixes = [...new Set(members.flatMap((f) => f.fixed_version ?? []))]
    const projects = [...new Set(members.map((f) => f.asset_id))]
    return {
      key,
      rule_id: members[0].rule_id,
      title: members[0].title,
      type: members[0].type,
      severity: severityRank[Math.min(...members.map((f) => severityRank.indexOf(f.severity)))],
      asset_ids: projects,
      project_count: projects.length,
      packages: [...new Set(members.flatMap((f) => f.package_name ?? []))],
      fixed_versions: fixes,
      ...(fixes.length === 1 ? { fixed_version: fixes[0] } : {}),
      findings: members,
    }
  })
}

function findingList(query: URLSearchParams): S['FindingList'] {
  const rows = filtered(query)
  const limit = Number(query.get('limit') ?? 50)
  const offset = Number(query.get('offset') ?? 0)
  const grouped = query.get('view') === 'grouped'
  const groups = grouped ? groupFindings(rows) : []
  return {
    findings: grouped ? [] : rows.slice(offset, offset + limit),
    groups: groups.slice(offset, offset + limit),
    total: grouped ? groups.length : rows.length,
    total_findings: rows.length,
    limit,
    offset,
  }
}

function dashboard(): S['Dashboard'] {
  const open = findings.filter((f) => !hidden(f))
  const byType = Object.fromEntries(types.map((type) => [type, open.filter((f) => f.type === type).length])) as S['TypeTotals']
  const views = assets.map(assetView)
  return {
    totals_by_severity: countOpen(findings),
    totals_by_type: byType,
    top_assets: views
      .map((item) => ({
        asset_id: item.id,
        display_name: item.display_name,
        kind: item.kind,
        score: item.open_counts.critical * 10 + item.open_counts.high * 5 + item.open_counts.medium * 2 + item.open_counts.low,
        critical: item.open_counts.critical,
        high: item.open_counts.high,
        medium: item.open_counts.medium,
        low: item.open_counts.low,
      }))
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score),
    trend: views.filter((item) => item.last_scan).map((item) => ({
      asset_id: item.id,
      scans: scans.filter((scan) => scan.asset_id === item.id && scan.status === 'succeeded').map((scan, index) => ({
        scan_id: scan.id,
        finished_at: scan.finished_at,
        critical_high_open: item.open_counts.critical + item.open_counts.high + (3 - Math.min(index, 3)) * 2,
      })),
    })),
    last_scans: views.flatMap((item) =>
      item.last_scan
        ? [{ asset_id: item.id, display_name: item.display_name, scan_id: item.last_scan.scan_id, status: item.last_scan.status, finished_at: item.last_scan.finished_at }]
        : [],
    ),
  }
}

function fixPlan(assetId: number): S['FixPlan'] {
  const rows = findings.filter((f) => f.asset_id === assetId && f.package_name && !hidden(f))
  const byPackage = new Map<string, Finding[]>()
  for (const row of rows) byPackage.set(row.package_name ?? '', [...(byPackage.get(row.package_name ?? '') ?? []), row])
  const plan: S['FixPlan'] = { steps: [], no_fix: [] }
  for (const [name, members] of byPackage) {
    const base = { ecosystem: members[0].ecosystem ?? 'npm', package: name, finding_count: members.length, severity_counts: countOpen(members), finding_ids: members.map((f) => f.id) }
    const target = members.find((f) => f.fixed_version)?.fixed_version
    if (!target) {
      plan.no_fix.push(base)
      continue
    }
    const score = members.length * 7
    plan.steps.push({
      ...base,
      installed_versions: [...new Set(members.flatMap((f) => f.package_version ?? []))],
      target_version: target,
      approximate: name === 'openssl',
      score,
      factors: [
        { name: 'severity', value: score, detail: `${String(members.length)} open findings` },
        { name: 'epss', value: 1.4, detail: 'highest EPSS 14%' },
        { name: 'reachability', value: 1.5, detail: 'reachable' },
      ],
      ...(name === 'axios' ? { pull_request: { number: 214, url: 'https://github.com/acme/payments-api/pull/214', state: 'open' as const } } : {}),
    })
  }
  plan.steps.sort((a, b) => b.score - a.score)
  return plan
}

function scanDiff(id: number): S['ScanDiff'] {
  const scan = scans.find((item) => item.id === id)
  const rows = findings.filter((f) => f.asset_id === scan?.asset_id)
  const fresh = rows.slice(0, 5)
  const fixed = rows.slice(5, 9)
  const persisting = rows.slice(9)
  return {
    scan_id: id,
    ...(id % 10 > 0 ? { against_scan_id: id - 1 } : {}),
    new: fresh,
    fixed,
    persisting,
    counts: { new: countOpen(fresh), fixed: countOpen(fixed), persisting: countOpen(persisting) },
  }
}

function broadcast(event: S['ScanEvent']) {
  for (const client of clients) client.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
}

/** queueScan plays a scan's whole lifecycle in about eight seconds. */
function queueScan(assetId: number): S['QueuedScan'] {
  const scan: Scan = { id: nextScanId++, asset_id: assetId, target_ref: assets.find((item) => item.id === assetId)?.ref, status: 'queued', trigger: 'ui', counts: zero() }
  scans.push(scan)
  const base = { scan_id: scan.id, asset_id: assetId }
  broadcast({ ...base, type: 'scan.queued', status: 'queued' })
  const stages: Pick<S['ScanEvent'], 'stage' | 'scanner'>[] = [
    { stage: 'resolve' },
    { stage: 'fetch' },
    { stage: 'scan', scanner: 'trivy' },
    { stage: 'scan', scanner: 'gitleaks' },
    { stage: 'normalize' },
  ]
  const steps = stages.map((stage, index) =>
    setTimeout(() => {
      scan.status = 'running'
      scan.started_at ??= new Date().toISOString()
      broadcast({ ...base, ...stage, type: 'scan.progress', status: 'running' })
    }, (index + 1) * 1400),
  )
  steps.push(
    setTimeout(() => {
      scan.status = 'succeeded'
      scan.finished_at = new Date().toISOString()
      scan.counts = countOpen(findings.filter((f) => f.asset_id === assetId))
      timers.delete(scan.id)
      broadcast({ ...base, type: 'scan.finished', status: 'succeeded' })
    }, 8400),
  )
  timers.set(scan.id, steps)
  return base
}

function decide(assetId: number, fingerprint: string, body: Partial<S['SetFindingStateRequest']>) {
  const row = findings.find((f) => f.asset_id === assetId && f.fingerprint === fingerprint)
  if (row) Object.assign(row, { status: 'ignored', state: body.state, reason: body.reason, expires_at: body.expires_at, decided_by: 'user', rule_ref: undefined, expired: false })
}

function clearDecision(row: Finding) {
  for (const key of ['state', 'reason', 'expires_at', 'decided_by', 'rule_ref', 'expired'] as const) delete row[key]
  row.status = 'open'
}

function applyRule(rule: S['FindingRule']) {
  for (const row of findings) {
    if (row.state || row.type === 'malware' || (row.type === 'secret' && rule.finding_type !== 'secret')) continue
    if (rule.asset_id !== undefined && rule.asset_id !== row.asset_id) continue
    if (rule.finding_type && rule.finding_type !== row.type) continue
    if (rule.rule_id && rule.rule_id !== row.rule_id) continue
    if (rule.package_name && rule.package_name !== row.package_name) continue
    if (rule.path_glob && !new RegExp(`^${rule.path_glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`).test(row.location ?? '')) continue
    Object.assign(row, { status: 'ignored', state: rule.state, reason: rule.reason, expires_at: rule.expires_at, decided_by: 'user', rule_ref: rule.id })
  }
}

const NOT_FOUND = Symbol('not found')
const NO_CONTENT = Symbol('no content')

function route(method: string, path: string, query: URLSearchParams, body: Record<string, unknown>): unknown {
  const parts = path.split('/').slice(2)
  const [head, rawId, sub, third] = parts
  const id = Number(rawId)
  const key = `${method} ${head}`

  if (head in settings && !rawId) {
    if (method === 'GET') return settings[head]
    if (method === 'PUT') return Object.assign(settings[head], body)
  }

  switch (key) {
    case 'GET health': return { status: 'ok', version: '0.6.0-preview' }
    case 'GET llm':
      // The model list the AI tab offers next to its free-text field.
      if (rawId === 'models') return { models: ['llama3.1', 'qwen3:14b', 'mistral-nemo'] }
      return NOT_FOUND
    case 'GET mcp': return { command: 'bastion', args: ['mcp'] }
    case 'GET update':
      if (rawId) return NOT_FOUND
      return { current: 'v0.5.1', disabled: false, latest: 'v0.6.0', update_available: consent === 'on', consent, command: 'brew upgrade bastion', release_url: 'https://github.com/ozerozdas/bastion/releases' }
    case 'PUT update':
    case 'POST update':
      consent = body.enabled ? 'on' : 'off'
      return { current: 'v0.5.1', disabled: false, update_available: false, consent }
    case 'GET trivy-db': return trivy
    case 'POST trivy-db':
      trivy = { state: 'ready', updated_at: new Date().toISOString(), trigger: 'user' }
      return trivy
    case 'GET connections':
      if (sub === 'discover') {
        return {
          repos: [
            { full_name: 'acme/payments-api', default_branch: 'main', private: true, archived: false, already_added: true },
            { full_name: 'acme/mobile-app', default_branch: 'main', private: true, archived: false, already_added: false },
            { full_name: 'acme/old-website', default_branch: 'master', private: false, archived: true, already_added: false },
          ],
          ecr_repositories: [{ name: 'orders', uri: '123456789012.dkr.ecr.eu-west-1.amazonaws.com/orders', tags: [{ tags: ['2026.11.3', 'latest'], digest: 'sha256:9f2c1e', ref: '123456789012.dkr.ecr.eu-west-1.amazonaws.com/orders:2026.11.3', pushed_at: ago(30), already_added: true }] }],
        }
      }
      return { connections }
    case 'POST connections': {
      if (sub === 'test') return connections.find((item) => item.id === id) ?? NOT_FOUND
      const created: S['Connection'] = { id: nextId++, kind: body.kind as S['ConnectionKind'], name: String(body.name), status: 'ok', ecr_asset_count: 0, created_at: new Date().toISOString() }
      connections.push(created)
      return created
    }
    case 'PATCH connections': {
      const found = connections.find((item) => item.id === id)
      return found ? Object.assign(found, body) : NOT_FOUND
    }
    case 'DELETE connections':
      connections.splice(connections.findIndex((item) => item.id === id), 1)
      return NO_CONTENT
    case 'GET docker':
      return { available: true, host: 'unix:///var/run/docker.sock', images: [
        { reference: 'ghcr.io/acme/payments-api:1.42.0', id: 'sha256:aa11', size_bytes: 248_000_000, created_at: ago(50) },
        { reference: 'postgres:17-alpine', id: 'sha256:bb22', size_bytes: 112_000_000, created_at: ago(400) },
      ] }
    case 'GET assets':
      if (sub === 'fix-plan') return fixPlan(id)
      return { assets: assets.map(assetView) }
    case 'POST assets': {
      if (sub === 'fix-plan') return { url: 'https://github.com/acme/payments-api/pull/215', number: 215, branch: 'bastion/fix-preview', manifest: 'package.json' }
      if (sub === 'findings' && parts[4] === 'explain') {
        return { model: 'qwen3:14b', text: 'This package accepts attacker-controlled input before validating it.\n\nUpgrade to the fixed version. If you cannot upgrade yet, reject unexpected keys at the API boundary.' }
      }
      const created = asset(nextId++, body.kind as S['AssetKind'], String(body.ref))
      assets.push(created)
      return assetView(created)
    }
    case 'PUT assets': {
      const found = assets.find((item) => item.id === id)
      if (!found) return NOT_FOUND
      if (sub === 'schedule') found.scan_schedule = body.schedule as S['AssetScanSchedule']
      if (sub === 'link') {
        const repo = assets.find((item) => item.id === body.repo_asset_id)
        if (repo) found.linked_repo = link(repo.id, repo.ref, 'manual')
      }
      return assetView(found)
    }
    case 'DELETE assets': {
      const index = assets.findIndex((item) => item.id === id)
      if (index < 0) return NOT_FOUND
      if (sub === 'link') delete assets[index].linked_repo
      else assets.splice(index, 1)
      return NO_CONTENT
    }
    case 'GET scans': {
      if (!rawId) {
        const sort = query.get('sort')
        const direction = query.get('order') === 'desc' ? -1 : 1
        const scanValue = (scan: Scan): string => {
          switch (sort) {
            case 'status':
              return scan.status
            case 'project':
              return assets.find((item) => item.id === scan.asset_id)?.ref ?? ''
            case 'findings':
              return String(
                Object.values(scan.counts).reduce((sum, n) => sum + n, 0),
              )
            case 'duration':
              return String(
                (scan.finished_at === undefined
                  ? 0
                  : Date.parse(scan.finished_at)) -
                  Date.parse(scan.started_at ?? ''),
              )
            case 'started':
              return scan.started_at ?? ''
            default:
              return scan.finished_at ?? '9'
          }
        }
        const rows = scans
          .filter((scan) => !query.has('asset_id') || scan.asset_id === Number(query.get('asset_id')))
          .filter((scan) => assets.some((item) => item.id === scan.asset_id))
          .sort((a, b) =>
            sort === null
              ? (b.finished_at ?? '9').localeCompare(a.finished_at ?? '9')
              : direction * scanValue(a).localeCompare(scanValue(b)) || b.id - a.id,
          )
        const limit = Number(query.get('limit') ?? 50)
        const offset = Number(query.get('offset') ?? 0)
        return { scans: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
      }
      if (sub === 'diff') return scanDiff(id)
      if (sub === 'findings') {
        const rows = findings.filter((f) => f.asset_id === scans.find((scan) => scan.id === id)?.asset_id)
        return { findings: rows, groups: [], total: rows.length, total_findings: rows.length, limit: rows.length, offset: 0 }
      }
      return scans.find((scan) => scan.id === id) ?? NOT_FOUND
    }
    case 'POST scans': {
      if (sub === 'cancel') {
        const scan = scans.find((item) => item.id === id)
        if (!scan) return NOT_FOUND
        timers.get(id)?.forEach(clearTimeout)
        timers.delete(id)
        scan.status = 'canceled'
        scan.finished_at = new Date().toISOString()
        broadcast({ type: 'scan.finished', scan_id: id, asset_id: scan.asset_id, status: 'canceled' })
        return scan
      }
      return { scans: (body.asset_ids as number[]).map(queueScan) }
    }
    case 'GET findings': return findingList(query)
    case 'POST findings': {
      if (rawId === 'state') {
        for (const fingerprint of body.fingerprints as string[]) decide(Number(body.asset_id), fingerprint, body)
        return NO_CONTENT
      }
      decide(Number(body.asset_id), rawId, body)
      return NO_CONTENT
    }
    case 'DELETE findings': {
      const row = findings.find((f) => f.fingerprint === rawId && f.asset_id === Number(query.get('asset_id')))
      if (row) clearDecision(row)
      return NO_CONTENT
    }
    case 'GET finding-rules': return { rules: rules.map(ruleView) }
    case 'POST finding-rules': {
      if (sub === 'approve') {
        const rule = rules.find((item) => item.id === id)
        if (!rule) return NOT_FOUND
        rule.status = 'active'
        applyRule(rule)
        return NO_CONTENT
      }
      const rule = { ...body, id: nextId++, status: 'active', created_by: 'user', created_at: new Date().toISOString(), matched: 0 } as S['FindingRule']
      rules.unshift(rule)
      applyRule(rule)
      return NO_CONTENT
    }
    case 'DELETE finding-rules': {
      findings.filter((f) => f.rule_ref === id).forEach(clearDecision)
      rules.splice(rules.findIndex((item) => item.id === id), 1)
      return NO_CONTENT
    }
    case 'POST notifications': return NO_CONTENT
    case 'GET reports': return third === undefined ? dashboard() : NOT_FOUND
    default: return NOT_FOUND
  }
}

function send(res: Res, status: number, type: string, body: string) {
  res.statusCode = status
  res.setHeader('Content-Type', type)
  res.end(body)
}

function download(path: string, query: URLSearchParams, res: Res): boolean {
  if (path === '/api/findings/export') {
    const rows = filtered(query)
    if (query.get('format') === 'json') send(res, 200, 'application/json', JSON.stringify(rows))
    else send(res, 200, 'text/csv', ['severity,type,title', ...rows.map((f) => `${f.severity},${f.type},"${f.title}"`)].join('\n'))
    return true
  }
  if (/^\/api\/scans\/\d+\/sbom$/.test(path)) {
    send(res, 200, 'application/json', JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] }))
    return true
  }
  return false
}

export function mockApi(): Plugin {
  return {
    name: 'bastion-mock-api',
    configureServer(server) {
      setInterval(() => {
        for (const client of clients) client.write(': ping\n\n')
      }, 15_000)

      server.middlewares.use((rawReq: unknown, rawRes: unknown, next: () => void) => {
        const req = rawReq as Req
        const res = rawRes as Res
        const url = new URL(req.url ?? '/', 'http://preview')
        if (!url.pathname.startsWith('/api/')) return next()

        if (url.pathname === '/api/events') {
          res.setHeader('Content-Type', 'text/event-stream')
          res.setHeader('Cache-Control', 'no-cache')
          res.write(': connected\n\n')
          clients.add(res)
          req.on('close', () => clients.delete(res))
          return
        }
        if (download(url.pathname, url.searchParams, res)) return

        let text = ''
        req.on('data', (chunk) => (text += String(chunk)))
        req.on('end', () => {
          const method = req.method ?? 'GET'
          const result = route(method, url.pathname, url.searchParams, text ? (JSON.parse(text) as Record<string, unknown>) : {})
          if (result === NO_CONTENT) {
            res.statusCode = 204
            res.end()
          } else if (result === NOT_FOUND) {
            console.warn(`[ui-preview] no mock for ${method} ${url.pathname}`)
            send(res, 404, 'application/problem+json', JSON.stringify({ type: 'about:blank', title: 'Not Found', status: 404, detail: 'The preview has no data for this request.' }))
          } else {
            send(res, 200, 'application/json', JSON.stringify(result))
          }
        })
      })
    },
  }
}
