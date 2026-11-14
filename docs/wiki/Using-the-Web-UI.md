# Using the Web UI

The left navigation has four sections: Dashboard, Findings, Projects (with **Projects |
Scans** tabs) and Connections.

## Sidebar

The footer of the sidebar reports the vulnerability DB. When it is missing, **Download
(~1.7 GB)** fetches it in the background — or the first scan that needs it starts the same
download — and the line shows progress (a scan-started download says so). A failed
download shows the error and a **Retry** button. Opening the UI only reads the status;
nothing is downloaded until you ask or a scan runs.

## Dashboard

The overview across all projects:

- open findings by severity (critical / high / medium / low) and by type,
- the riskiest projects,
- when each project was last scanned.

A **Get started** card at the top ticks off four steps — connect GitHub, add a
project, run the first scan and scan in CI or from the CLI — from the data the
page already has. It hides once all four are done, or when you dismiss it; the
CLI step and the dismissal are remembered in this browser only.

## Findings

Findings from the **latest scan of every project** — one list for "what is critical
anywhere?". No project selected means all of them.

- **Project** — each row names the project it belongs to. The **Project** filter narrows
  the list to one project; a **View findings** link on a Projects row opens this page with
  that filter already set. Older `/reports` and `/security-reports` links redirect here.
- **Filter** by project, type (vulnerability, secret, misconfiguration, licence), severity
  and status. Findings are severity-ordered, critical first.
- **Detail** — description, location, package and installed version, the **fixed version**,
  the scanner and rule that produced it, and references.
- **Hide a finding** as *ignored*, *accepted risk* or *false positive*, one at a time or in
  bulk across projects. A reason is required. The decision sticks to the finding's
  fingerprint (its project plus the issue found), so it applies to later scans of the same
  project too — see [Findings](Findings.md#ignoring-findings).
- **Grouped view** — grouped is the default; the **Single / Grouped** toggle flips it. The
  toggle only appears while every project is listed, since grouped folds one rule into one
  row across projects showing its worst severity, how many projects it reaches and the
  fixed version. Opting out is part of the URL (`/findings?view=single`). Opening a grouped
  row lists every affected project, and hiding it there applies one decision to all of them
  after a confirm step that states the count.

## Projects

Every scannable thing is a *project* (internally an *asset*):

| Kind | How to add |
|---|---|
| GitHub repository | **List repositories** (repos the token can see), or type any public repo as `owner/name` |
| Local directory | **Add a local path** with an absolute path |

Each row shows the last scan status and severity counts. **Scan** queues a scan; progress
streams live. A GitHub scan resolves the default branch to a commit SHA, downloads that
tarball, scans it and deletes the workspace afterwards.

The page has two tabs: **Projects** (the table above) and **Scans**. The tab is part of
the URL (`/projects?tab=scans`), so a reload or a shared link keeps it; the old
`/scan-history` URL opens the Scans tab.

### Scans

Every past scan with its status, trigger, duration and error (if any). A failed scan shows
a human-readable cause and a suggested next step. The **Project** filter is part of the URL
(`/projects?tab=scans&asset=<id>`), so a filtered list can be bookmarked.

Every succeeded scan has a **Compare** link. It opens `/scans/<id>/diff` and compares that
scan with the previous succeeded scan of the same project, grouping findings as **New**,
**Fixed** and **Persisting** with the same drawer as Findings; a fixed finding opens
read-only, because it is already gone from the newer scan. **Compare with** picks any other
succeeded scan of the project and is part of the URL (`?against=<id>`), so a comparison can
be bookmarked, and **← Scans** returns to the project's filtered Scans tab.

Every succeeded scan also has a **CycloneDX** link in the SBOM column: it downloads the
scan's package inventory as a CycloneDX 1.6 JSON BOM (`GET /api/scans/<id>/sbom`).

## Connections

Where credentials live. In v0.1 this is **GitHub** only.

- **Add** — paste a read-only token (see [Getting Started](Getting-Started.md#3-connect-github-optional)).
  It is stored in the OS keychain.
- **Test** — calls `GET /user` and shows which GitHub login the token belongs to.
- **Remove** — deletes the connection and its keychain entry.
