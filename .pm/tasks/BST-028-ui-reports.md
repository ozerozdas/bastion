---
id: BST-028
title: "UI: Security Reports (findings table, drawer, ignore)"
phase: P1
status: review
owner_role: coder
depends_on: [BST-024, BST-025]
estimate: L
---

## Context
§7.4.

## Scope
- In: per-asset findings table with type/severity/status filters, scanner + rule shown on every row, detail drawer (description, fixed version, references, occurrences, location), ignore/unignore with reason. License findings labelled informational.
- Out: fix plan tab (P3).

## Acceptance criteria
- [x] Description and references rendered as plain text / safe links only (scanner output is untrusted, §4.3)
- [x] `make web-check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log

- `web/src/pages/reports.tsx`: project picker (from `assetsQuery`, default first asset), type/severity/status selects (status defaults to open, ignored selectable), findings table (severity badge, type, `rule_id`, `package@version` plus `fixed_version` or `location`, title with occurrences when >1, scanner; license rows marked "informational"), empty states (no projects → link to Projects; none open → "No open findings in the latest scan"), errors show the problem detail.
- Row click (or Enter/Space on the focused row) opens a plain-div drawer: `role="dialog"`, `aria-modal`, focus moved to the panel on open, Escape and Close close it. Title, severity/type/state badges, description as plain text in a `whitespace-pre-wrap` `<p>` (no `dangerouslySetInnerHTML`, no markdown), fix, location, occurrences, first-seen scan id, fingerprint in monospace.
- References: only values matching `https://` become links (`target="_blank" rel="noreferrer noopener"`); everything else renders as plain text.
- Decision form (select ignored | accepted_risk | false_positive + required reason textarea) → `useSetFindingState`; when a decision exists the drawer shows state + reason and a Reopen button → `useClearFindingState`. Success closes the drawer because the invalidated list moves the finding between the open/ignored filters.
- `web/src/router.tsx`: `/security-reports` gained `validateSearch` for the optional `?asset=<id>` search param (positive integer, string or number). No other route changed.
- Verified: `make web-check`, `npm run build --prefix web`, and `make check` all pass; `vite preview` loads `/security-reports` without a runtime error (shows the "Projects failed to load" error state with no backend). Data-populated rendering was not checked by eye: no seeded DB in this worktree.
