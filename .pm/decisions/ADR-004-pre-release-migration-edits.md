# ADR-004: Migrations may be edited before the first release

- Status: accepted (orchestrator, 2026-11-11)
- Date: 2026-11-11
- Task: BST-010 (review fixes), applies repo-wide
- Deciders: Özer (human), orchestrator, coder agent
- Spec refs: §5 (data model), §9.1 (schema changes), §11.3.5

## Context

§9.1 requires a new goose migration for every schema change and forbids editing
applied migrations. That rule protects users whose databases already ran a
migration. Bastion is pre-release: no tagged release exists, `db/migrations/00001_init.sql`
has only ever run against throwaway local/dev databases, and the store is not yet
wired into the server. Editing `00001` is therefore not a destructive change for
anyone, while splitting schema fixes into follow-up migrations would leave the
initial schema permanently carrying known-wrong comments and a missing column.

## Decision

`db/migrations/00001_init.sql` may be edited directly until the first tagged
release (`v0.1.0`). After `v0.1.0` is tagged, never: from that point every schema
change ships as a new migration file, per §9.1.

## Consequences

- Pre-release databases (local dev only) must be recreated; that is acceptable
  and no export/import path is provided.
- The initial schema stays readable: wrong comments and missing columns are
  fixed in place (`occurrences`, secret-location comment).
- The exception ends at the `v0.1.0` tag; this ADR must not be cited after it.
