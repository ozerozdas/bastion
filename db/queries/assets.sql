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

-- name: GetAsset :one
SELECT * FROM assets WHERE id = sqlc.arg(id);

-- name: ListAssets :many
SELECT * FROM assets WHERE archived_at IS NULL ORDER BY display_name, id;
