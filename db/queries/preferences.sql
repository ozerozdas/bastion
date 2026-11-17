-- name: ListPreferences :many
SELECT "key", value FROM preferences ORDER BY "key";

-- name: UpsertPreference :exec
-- A PUT merges: only the keys it carries change, and updated_at moves so a
-- diagnostic can tell when the value was last written.
INSERT INTO preferences ("key", value)
VALUES (sqlc.arg(key), sqlc.arg(value))
ON CONFLICT ("key") DO UPDATE
SET value = excluded.value,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
