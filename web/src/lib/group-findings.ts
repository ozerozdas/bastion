import type { Finding, FindingType, Severity } from '../api/findings'

/** severityRank orders severities worst first, matching the API's list order. */
const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
}

export type FindingGroup = {
  /** Stable key for React and selection: the rule id (or fingerprint) plus the type. */
  key: string
  /** Absent when the scanner reported no rule id; key then falls back to the fingerprint. */
  ruleId: string | undefined
  /** The first member's title; rows of one rule usually share it. */
  title: string
  type: FindingType
  /** The worst severity among the members. */
  severity: Severity
  /** Every member, in the order the API returned them. */
  findings: Finding[]
  /** Distinct asset ids with this rule, in first-seen order. */
  assetIds: number[]
  projectCount: number
  /** Distinct member fixed versions, in first-seen order. */
  fixedVersions: string[]
  /** The fixed version when every member agrees on one; undefined otherwise. */
  fixedVersion: string | undefined
}

/**
 * groupFindings folds the cross-project list into one row per rule + type, so a
 * CVE present in several projects is one row (#90). It is pure: the page owns
 * the filters, and grouping only reorders what they returned.
 *
 * A finding without a rule id groups by its fingerprint instead, which is
 * per-project, so it only joins identical fingerprints from other projects.
 */
export function groupFindings(findings: readonly Finding[]): FindingGroup[] {
  const groups = new Map<string, FindingGroup>()

  for (const finding of findings) {
    const ruleId = finding.rule_id?.trim() ? finding.rule_id : undefined
    const key = `${ruleId ?? finding.fingerprint}\u0000${finding.type}`
    let group = groups.get(key)
    if (group === undefined) {
      group = {
        key,
        ruleId,
        title: finding.title,
        type: finding.type,
        severity: finding.severity,
        findings: [],
        assetIds: [],
        projectCount: 0,
        fixedVersions: [],
        fixedVersion: undefined,
      }
      groups.set(key, group)
    }

    group.findings.push(finding)
    if (!group.assetIds.includes(finding.asset_id)) {
      group.assetIds.push(finding.asset_id)
    }
    if (severityRank[finding.severity] < severityRank[group.severity]) {
      group.severity = finding.severity
    }
    if (
      finding.fixed_version !== undefined &&
      finding.fixed_version !== '' &&
      !group.fixedVersions.includes(finding.fixed_version)
    ) {
      group.fixedVersions.push(finding.fixed_version)
    }
  }

  const ordered = [...groups.values()]
  for (const group of ordered) {
    group.projectCount = group.assetIds.length
    const [only] = group.fixedVersions
    group.fixedVersion =
      group.fixedVersions.length === 1 ? only : undefined
  }

  return ordered.sort(
    (a, b) =>
      severityRank[a.severity] - severityRank[b.severity] ||
      b.findings.length - a.findings.length ||
      a.title.localeCompare(b.title),
  )
}
