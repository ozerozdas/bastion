-- name: CreateScan :one
INSERT INTO scans (asset_id, target_ref, status, "trigger", started_at)
VALUES (
    sqlc.arg(asset_id),
    sqlc.narg(target_ref),
    sqlc.arg(status),
    sqlc.arg(trigger),
    sqlc.arg(started_at)
)
RETURNING *;
