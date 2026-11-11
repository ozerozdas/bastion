-- name: CreateAsset :one
INSERT INTO assets (kind, connection_id, display_name, ref, default_branch, metadata_json, created_at)
VALUES (
    sqlc.arg(kind),
    sqlc.narg(connection_id),
    sqlc.arg(display_name),
    sqlc.arg(ref),
    sqlc.narg(default_branch),
    sqlc.arg(metadata_json),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: GetOrCreateAsset :one
-- Resolve the asset a scan targets, creating it the first time it is seen. A
-- repeat target keeps its row and id (findings fingerprints depend on the id);
-- only the display fields are refreshed, and optional fields are filled when
-- the caller provides them but never cleared.
INSERT INTO assets (kind, connection_id, display_name, ref, default_branch, metadata_json, created_at)
VALUES (
    sqlc.arg(kind),
    sqlc.narg(connection_id),
    sqlc.arg(display_name),
    sqlc.arg(ref),
    sqlc.narg(default_branch),
    sqlc.arg(metadata_json),
    sqlc.arg(created_at)
)
ON CONFLICT (kind, ref) DO UPDATE SET
    display_name   = excluded.display_name,
    connection_id  = COALESCE(excluded.connection_id, assets.connection_id),
    default_branch = COALESCE(excluded.default_branch, assets.default_branch)
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets WHERE id = sqlc.arg(id);

-- name: ArchiveAsset :one
-- Soft delete: the row stays so historical scans keep their findings.
UPDATE assets SET archived_at = sqlc.arg(archived_at) WHERE id = sqlc.arg(id)
RETURNING *;

-- name: ListAssets :many
SELECT * FROM assets WHERE archived_at IS NULL ORDER BY display_name, id;
