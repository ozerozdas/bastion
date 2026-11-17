-- name: CreateConnection :one
-- A duplicate (kind, name) is a no-op conflict rather than an error: the
-- service maps the resulting sql.ErrNoRows to ErrConflict. Inserting first and
-- storing the secret afterwards means the keyring key can carry the row id
-- (bastion.connection.<id>).
INSERT INTO connections (kind, name)
VALUES (sqlc.arg(kind), sqlc.arg(name))
ON CONFLICT (kind, name) DO NOTHING
RETURNING *;

-- name: GetConnection :one
SELECT * FROM connections WHERE id = sqlc.arg(id);

-- name: ListConnections :many
SELECT * FROM connections ORDER BY kind, name, id;

-- name: SetConnectionSecretRef :execrows
-- Point the row at the keyring key that holds its credential.
UPDATE connections
SET secret_ref = sqlc.arg(secret_ref)
WHERE id = sqlc.arg(id);

-- name: SetConnectionConfig :one
-- Store the non-secret configuration a kind needs at create time (an AWS
-- profile and region). GitHub writes its identity through SetConnectionStatus.
UPDATE connections
SET config_json = sqlc.arg(config_json)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetConnectionStatus :one
-- Record one test result. config_json holds non-secret values only (the GitHub
-- login and the last failure hint).
UPDATE connections
SET status = sqlc.arg(status),
    last_checked_at = sqlc.arg(last_checked_at),
    config_json = sqlc.arg(config_json)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: RenameConnection :one
-- A name is unique per kind. The guard turns a taken name into no rows instead
-- of a driver-level UNIQUE error; the service maps that to ErrConflict once the
-- id is known to exist.
UPDATE connections
SET name = sqlc.arg(name)
WHERE connections.id = sqlc.arg(id)
  AND NOT EXISTS (
    SELECT 1
    FROM connections AS other
    WHERE other.kind = connections.kind
      AND other.name = sqlc.arg(name)
      AND other.id <> connections.id
  )
RETURNING *;

-- name: DeleteConnection :execrows
DELETE FROM connections WHERE id = sqlc.arg(id);

-- name: ListRepoAssetRefs :many
-- Repositories that already exist as assets. Deliberately not filtered by
-- connection: assets are unique per (kind, ref), so a repo added by the CLI or
-- another connection is already present for this one too.
SELECT ref FROM assets WHERE kind = 'repo';
