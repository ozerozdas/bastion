# Bastion security report

Generated 2026-11-27 09:30 UTC · Scope: whole fleet

## Coverage

2 assets: 1 scanned, 1 never scanned, 0 last scan failed.

| Asset | Kind | Last scan status | Finished | Failed scanners |
| --- | --- | --- | --- | --- |
| Alpha \| repo | repo | succeeded | 2026-11-27 09:20 UTC | gitleaks |
| Beta | path | never scanned | — | — |

## Open findings

3 open: 1 critical, 1 high, 0 medium, 1 low, 0 unknown.

| Asset | Kind | Total | Critical | High | Medium | Low | Unknown |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Alpha \| repo | repo | 2 | 1 | 1 | 0 | 0 | 0 |
| Beta | path | 1 | 0 | 0 | 0 | 1 | 0 |

## SLA

Thresholds: 7 days critical, 30 days high, 90 days medium, 180 days low. Fix window: 90 days.

3 open, 1 overdue, 2 fixed in the window, mean time to fix 12.5 days.

| Asset | Finding | Severity | First seen | Age days | Threshold days | Overdue days |
| --- | --- | --- | --- | --- | --- | --- |
| Alpha \| repo | CVE-2026-0001 \| remote code | critical | 2026-09-01 10:00 UTC | 87 | 7 | 80 |

## Triage decisions

2 decisions, 1 expired.

By state: ignored 1, accepted_risk 1, false_positive 0.

By decided by: user 1, agent 1.

| Asset | Finding | Severity | State | Reason | Decided by | Expires | Expired |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Alpha \| repo | S3 bucket public | high | accepted_risk | GPL \| needs &lt;script&gt;review<br>second line | agent | 2026-10-01 00:00 UTC | yes |
| Beta | lodash outdated | low | ignored | not deployed | user | — | no |

## Suppression rules

1 active, 1 proposed.

| ID | Asset | Finding type | Rule ID | Package | Path glob | State | Reason | Expires | Expired | Created by | Matched |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 5 | Alpha \| repo | vulnerability | CVE-2099-9999 | openssl | **/*.mod | ignored | not deployed | 2026-10-01 00:00 UTC | yes | user | 2 |

## Licence policy

Global allow: BSD-3-Clause

Global deny: GPL-3.0, AGPL-3.0

| Asset | Allow | Deny |
| --- | --- | --- |
| Alpha \| repo | MIT | GPL-3.0 |

