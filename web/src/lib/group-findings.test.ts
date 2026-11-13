import { describe, expect, it } from 'vitest'

import type { Finding } from '../api/findings'
import { groupFindings } from './group-findings'

/** finding builds one normalized finding; only the fields a test sets differ. */
function finding(
  overrides: Partial<Finding> & Pick<Finding, 'asset_id' | 'fingerprint'>,
): Finding {
  return {
    id: 1,
    scan_id: 1,
    type: 'vulnerability',
    severity: 'medium',
    title: 'A finding',
    occurrences: 1,
    scanner: 'trivy',
    status: 'open',
    references: [],
    ...overrides,
  }
}

describe('groupFindings', () => {
  it('folds one CVE from two projects into a single group', () => {
    const groups = groupFindings([
      finding({
        asset_id: 1,
        fingerprint: 'fp-a',
        rule_id: 'CVE-2020-0001',
        severity: 'high',
        fixed_version: '4.17.21',
      }),
      finding({
        asset_id: 2,
        fingerprint: 'fp-b',
        rule_id: 'CVE-2020-0001',
        severity: 'critical',
        fixed_version: '4.17.21',
      }),
    ])

    expect(groups).toHaveLength(1)
    const [group] = groups
    expect(group.ruleId).toBe('CVE-2020-0001')
    expect(group.severity).toBe('critical')
    expect(group.projectCount).toBe(2)
    expect(group.assetIds).toEqual([1, 2])
    expect(group.fixedVersion).toBe('4.17.21')
    expect(group.findings).toHaveLength(2)
  })

  it('reports varying fixed versions instead of picking one', () => {
    const [group] = groupFindings([
      finding({ asset_id: 1, fingerprint: 'fp-a', rule_id: 'CVE-1', fixed_version: '1.2.3' }),
      finding({ asset_id: 2, fingerprint: 'fp-b', rule_id: 'CVE-1', fixed_version: '1.4.0' }),
    ])

    expect(group.fixedVersions).toEqual(['1.2.3', '1.4.0'])
    expect(group.fixedVersion).toBeUndefined()
  })

  it('leaves the fixed version empty when no member knows one', () => {
    const [group] = groupFindings([
      finding({ asset_id: 1, fingerprint: 'fp-a', rule_id: 'CVE-1' }),
      finding({ asset_id: 2, fingerprint: 'fp-b', rule_id: 'CVE-1' }),
    ])

    expect(group.fixedVersions).toEqual([])
    expect(group.fixedVersion).toBeUndefined()
  })

  it('groups by type as well as rule, so a secret and a CVE stay apart', () => {
    const groups = groupFindings([
      finding({ asset_id: 1, fingerprint: 'fp-a', rule_id: 'X-1', type: 'vulnerability' }),
      finding({ asset_id: 1, fingerprint: 'fp-b', rule_id: 'X-1', type: 'secret' }),
    ])

    expect(groups).toHaveLength(2)
    expect(groups.map((group) => group.type).sort()).toEqual(['secret', 'vulnerability'])
  })

  it('falls back to the fingerprint when the scanner reported no rule id', () => {
    const groups = groupFindings([
      finding({ asset_id: 1, fingerprint: 'shared-fp', rule_id: '' }),
      finding({ asset_id: 2, fingerprint: 'shared-fp', rule_id: '' }),
      finding({ asset_id: 2, fingerprint: 'other-fp', rule_id: undefined }),
    ])

    expect(groups).toHaveLength(2)
    const shared = groups.find((group) => group.key.startsWith('shared-fp'))
    expect(shared?.ruleId).toBeUndefined()
    expect(shared?.projectCount).toBe(2)
    expect(shared?.key).toBe(`shared-fp\u0000vulnerability`)
  })

  it('orders groups by worst severity, then by how many findings they hold', () => {
    const groups = groupFindings([
      finding({ asset_id: 1, fingerprint: 'fp-low', rule_id: 'LOW-1', severity: 'low' }),
      finding({ asset_id: 1, fingerprint: 'fp-high-1', rule_id: 'HIGH-1', severity: 'high' }),
      finding({ asset_id: 2, fingerprint: 'fp-high-2', rule_id: 'HIGH-1', severity: 'high' }),
      finding({ asset_id: 1, fingerprint: 'fp-crit', rule_id: 'CRIT-1', severity: 'critical' }),
      finding({ asset_id: 1, fingerprint: 'fp-unk', rule_id: 'UNK-1', severity: 'unknown' }),
      finding({ asset_id: 1, fingerprint: 'fp-med', rule_id: 'MED-1', severity: 'medium' }),
    ])

    expect(groups.map((group) => group.ruleId)).toEqual([
      'CRIT-1',
      'HIGH-1',
      'MED-1',
      'LOW-1',
      'UNK-1',
    ])
  })
})
