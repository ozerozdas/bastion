-- name: ListLicencePolicy :many
-- The rules of one scope: the global policy when asset_id is NULL, otherwise
-- that asset's policy. The caller resolves a per-asset rule over a global one.
SELECT licence, action
FROM licence_policy
WHERE ((sqlc.narg(asset_id) IS NULL AND asset_id IS NULL) OR asset_id = sqlc.narg(asset_id))
ORDER BY action, licence;

-- name: DeleteLicencePolicy :exec
-- Clears one scope before a replacement writes the new lists in the same
-- transaction, so a PUT is atomic.
DELETE FROM licence_policy
WHERE ((sqlc.narg(asset_id) IS NULL AND asset_id IS NULL) OR asset_id = sqlc.narg(asset_id));

-- name: InsertLicencePolicy :exec
INSERT INTO licence_policy (asset_id, licence, action)
VALUES (sqlc.narg(asset_id), sqlc.arg(licence), sqlc.arg(action));
