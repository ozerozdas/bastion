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

-- name: ListLinkedImageLatestFindingKeys :many
-- Vulnerability keys of each image linked to one repository, from that image's
-- newest succeeded scan. The fix plan's "latest image" factor (#29) asks
-- whether a step's fix ships in an image built from the repository. A finding
-- matches on rule id and package: the fingerprint embeds the asset id, so it
-- never matches across assets.
SELECT f.rule_id, f.package_name
FROM (
    SELECT l.image_asset_id,
           (SELECT MAX(s.id) FROM scans s
            WHERE s.asset_id = l.image_asset_id AND s.status = 'succeeded') AS scan_id
    FROM asset_links l
    WHERE l.repo_asset_id = sqlc.arg(repo_asset_id)
) linked
JOIN findings f ON f.scan_id = linked.scan_id
WHERE f.type = 'vulnerability'
  AND f.rule_id IS NOT NULL
  AND f.package_name IS NOT NULL
GROUP BY f.rule_id, f.package_name;

-- name: GetNewestLinkedImageScan :one
-- The newest succeeded scan among the images linked to one repository, with
-- the image it belongs to. The fix plan's "latest image" factor for an image
-- asset (#29) asks whether this image is that one. sql.ErrNoRows means no
-- linked image has finished a scan.
SELECT l.image_asset_id, MAX(s.id) AS scan_id
FROM asset_links l
JOIN scans s ON s.asset_id = l.image_asset_id AND s.status = 'succeeded'
WHERE l.repo_asset_id = sqlc.arg(repo_asset_id)
GROUP BY l.image_asset_id
ORDER BY scan_id DESC
LIMIT 1;

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
