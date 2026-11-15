-- name: SetManualAssetLink :one
-- A manual link always wins: it replaces a link the OCI labels created, and an
-- image links to at most one repository. The revision is only meaningful for a
-- label-derived link, so a manual one clears it.
INSERT INTO asset_links (repo_asset_id, image_asset_id, source, revision, created_at)
VALUES (
    sqlc.arg(repo_asset_id),
    sqlc.arg(image_asset_id),
    'manual',
    NULL,
    sqlc.arg(created_at)
)
ON CONFLICT (image_asset_id) DO UPDATE SET
    repo_asset_id = excluded.repo_asset_id,
    source        = 'manual',
    revision      = NULL,
    created_at    = excluded.created_at
RETURNING *;

-- name: UpsertOCIAssetLink :one
-- Auto-link from the image's OCI labels. A manual link is never overwritten:
-- the WHERE clause filters the conflicting row out, so the statement returns no
-- row and the caller keeps the manual choice.
INSERT INTO asset_links (repo_asset_id, image_asset_id, source, revision, created_at)
VALUES (
    sqlc.arg(repo_asset_id),
    sqlc.arg(image_asset_id),
    'oci',
    sqlc.narg(revision),
    sqlc.arg(created_at)
)
ON CONFLICT (image_asset_id) DO UPDATE SET
    repo_asset_id = excluded.repo_asset_id,
    revision      = excluded.revision
WHERE asset_links.source = 'oci'
RETURNING *;

-- name: ClearAssetLink :exec
DELETE FROM asset_links WHERE image_asset_id = sqlc.arg(image_asset_id);

-- name: ListAssetLinks :many
-- Every link with both ends' display fields, so one read decorates a whole
-- asset list instead of one query per row.
SELECT
    l.id,
    l.repo_asset_id,
    l.image_asset_id,
    l.source,
    l.revision,
    l.created_at,
    repo.ref          AS repo_ref,
    repo.display_name AS repo_display_name,
    image.ref         AS image_ref,
    image.display_name AS image_display_name
FROM asset_links l
JOIN assets repo ON repo.id = l.repo_asset_id
JOIN assets image ON image.id = l.image_asset_id
ORDER BY l.id;
