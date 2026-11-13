# Findings

Every scanner result is normalized into one **finding** model, whatever produced it.

## Types

| Type | Produced by | Example |
|---|---|---|
| `vulnerability` | Trivy and OSV | `CVE-2024-1234` in `lodash@4.17.20`, fixed in `4.17.21` |
| `license` | Trivy | A package under a licence you may need to review (informational in v0.1) |
| `misconfig` | Trivy | Dockerfile runs as root; S3 bucket without encryption |
| `secret` | Gitleaks | An AWS key committed in `config/prod.env` |
| `malware` | OSV | A `MAL-` advisory: a known-malicious package in the inventory (always critical) |

## One advisory, one finding

Trivy and OSV can report the same package advisory under different ids: Trivy
shows the CVE, OSV the GHSA. After normalization bastion merges findings of the
same package in the same location whose advisory alias sets intersect, keeping
Trivy's finding as the primary one. The merged finding lists every scanner that
reported it (`scanners` in the API), so one CVE appears once rather than twice.


## Severity

`critical` · `high` · `medium` · `low` · `unknown` — taken from the scanner. `--fail-on`
and the dashboard use this order.

## Fingerprints: what makes a finding "the same"

Each finding gets a fingerprint: a hash of

```
project · type · rule id (CVE / GHSA / rule) · ecosystem · package name · normalized location
```

What it deliberately **leaves out**:

- the **package version** — so a CVE stays the same finding after an unrelated bump, and
  disappears ("fixed") when an upgrade closes it;
- **line numbers** — they shift on every edit;
- temporary workspace paths.

If the same issue appears several times in one scan (e.g. two copies of a package in one
lockfile), it becomes **one** finding with an occurrence count; the highest severity wins.
When Trivy and OSV report one advisory under different ids, the merged finding keeps
Trivy's fingerprint, so scan diffs and ignore decisions stay stable.

## Ignoring findings

In **Findings** you can hide a finding as:

| State | Use it when |
|---|---|
| *ignored* | Not relevant here (e.g. dev-only tooling) |
| *accepted risk* | Real, but you've decided to live with it for now |
| *false positive* | The scanner is wrong |

A **reason is required**. The decision is stored against the fingerprint, so it survives
re-scans of the same project. Hidden findings don't count towards `--fail-on`, which only
looks at **open** findings.

## Secrets

Bastion never stores a raw secret. For each Gitleaks match it keeps:

- a **redacted** value — first four characters plus `****`,
- an **HMAC-SHA256** of the secret under a random 32-byte local key (kept in the OS
  keyring, or `BASTION_HMAC_KEY`).

The HMAC lets bastion recognise the same secret across scans without it being recoverable
from the database. A plain hash would not do: short secrets could be brute-forced.

Only the **working tree** is scanned in v0.1, not git history.

> If a secret shows up, **rotate it**. Deleting it from the file does not remove it from
> git history or from anyone who already cloned the repository.
