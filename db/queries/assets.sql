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

-- name: GetAssetByKindRef :one
SELECT * FROM assets WHERE kind = sqlc.arg(kind) AND ref = sqlc.arg(ref);

-- name: UnarchiveAsset :one
-- Re-adding an archived asset revives its row, so its historical scans and
-- findings keep pointing at the same id (fingerprints include it).
UPDATE assets SET archived_at = NULL WHERE id = sqlc.arg(id)
RETURNING *;

-- name: ListAssetSummaries :many
-- Every non-archived asset with its newest scan and the open severity counts of
-- its newest succeeded scan. The counts use the dashboard scope: a decision in
-- finding_states hides its finding, and a failed or running newest scan does
-- not shadow the last complete report.
WITH newest_scan AS (
    SELECT s.asset_id, s.id AS scan_id, s.status, s.finished_at
    FROM scans s
    WHERE s.id = (
        SELECT MAX(s2.id)
        FROM scans s2
        WHERE s2.asset_id = s.asset_id
    )
),
last_succeeded AS (
    SELECT s.asset_id, s.id AS scan_id
    FROM scans s
    WHERE s.status = 'succeeded'
      AND s.id = (
          SELECT MAX(s2.id)
          FROM scans s2
          WHERE s2.asset_id = s.asset_id AND s2.status = 'succeeded'
      )
),
open_severity AS (
    SELECT
        f.asset_id,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS open_critical,
        SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS open_high,
        SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS open_medium,
        SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS open_low,
        SUM(CASE WHEN f.severity = 'unknown' THEN 1 ELSE 0 END) AS open_unknown
    FROM findings f
    JOIN last_succeeded ls ON ls.scan_id = f.scan_id
    LEFT JOIN finding_states fs
        ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
    WHERE f.status = 'open' AND fs.id IS NULL
    GROUP BY f.asset_id
)
SELECT
    a.id,
    a.kind,
    a.connection_id,
    a.display_name,
    a.ref,
    a.default_branch,
    a.created_at,
    ns.scan_id AS last_scan_id,
    ns.status AS last_scan_status,
    ns.finished_at AS last_scan_finished_at,
    CAST(COALESCE(os.open_critical, 0) AS INTEGER) AS open_critical,
    CAST(COALESCE(os.open_high, 0) AS INTEGER) AS open_high,
    CAST(COALESCE(os.open_medium, 0) AS INTEGER) AS open_medium,
    CAST(COALESCE(os.open_low, 0) AS INTEGER) AS open_low,
    CAST(COALESCE(os.open_unknown, 0) AS INTEGER) AS open_unknown
FROM assets a
LEFT JOIN newest_scan ns ON ns.asset_id = a.id
LEFT JOIN open_severity os ON os.asset_id = a.id
WHERE a.archived_at IS NULL
ORDER BY a.display_name, a.id;
