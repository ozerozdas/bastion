# Using the Web UI

The UI has five pages in the left navigation.

## Dashboard

The overview across all projects:

- open findings by severity (critical / high / medium / low) and by type,
- the riskiest projects,
- when each project was last scanned.

## Connections

Where credentials live. In v0.1 this is **GitHub** only.

- **Add** — paste a read-only token (see [Getting Started](Getting-Started.md#3-connect-github-optional)).
  It is stored in the OS keychain.
- **Test** — calls `GET /user` and shows which GitHub login the token belongs to.
- **Remove** — deletes the connection and its keychain entry.

## Projects

Every scannable thing is a *project* (internally an *asset*):

| Kind | How to add |
|---|---|
| GitHub repository | **List repositories** (repos the token can see), or type any public repo as `owner/name` |
| Local directory | **Add a local path** with an absolute path |

Each row shows the last scan status and severity counts. **Scan** queues a scan; progress
streams live. A GitHub scan resolves the default branch to a commit SHA, downloads that
tarball, scans it and deletes the workspace afterwards.

## Security Reports

Findings from the **latest scan** of one project.

- **Filter** by type (vulnerability, secret, misconfiguration, licence), severity and status.
- **Detail** — description, location, package and installed version, the **fixed version**,
  the scanner and rule that produced it, and references.
- **Hide a finding** as *ignored*, *accepted risk* or *false positive*. A reason is
  required. The decision sticks to the finding's fingerprint, so it applies to later scans
  of the same project too — see [Findings](Findings.md#ignoring-findings).

## Scan History

Every past scan with its status, trigger, duration and error (if any). A failed scan shows
a human-readable cause and a suggested next step. Comparing two scans (new / fixed /
persisting) arrives in v0.2.
