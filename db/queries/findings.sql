-- name: InsertFinding :exec
INSERT INTO findings (
    scan_id,
    asset_id,
    type,
    fingerprint,
    occurrences,
    severity,
    title,
    rule_id,
    package_name,
    package_version,
    fixed_version,
    ecosystem,
    location,
    cvss,
    description,
    references_json,
    scanner,
    first_seen_scan_id,
    created_at
)
VALUES (
    sqlc.arg(scan_id),
    sqlc.arg(asset_id),
    sqlc.arg(type),
    sqlc.arg(fingerprint),
    sqlc.arg(occurrences),
    sqlc.arg(severity),
    sqlc.arg(title),
    sqlc.narg(rule_id),
    sqlc.narg(package_name),
    sqlc.narg(package_version),
    sqlc.narg(fixed_version),
    sqlc.narg(ecosystem),
    sqlc.narg(location),
    sqlc.narg(cvss),
    sqlc.narg(description),
    sqlc.arg(references_json),
    sqlc.arg(scanner),
    sqlc.arg(first_seen_scan_id),
    sqlc.arg(created_at)
);

-- name: EarliestScanIDForFingerprint :one
-- Earliest scan of the same asset that already carries the fingerprint; 0 when
-- this is its first appearance. The current scan has no row for the
-- fingerprint yet (one finding per fingerprint per scan), so callers can use
-- their own scan id as the fallback.
SELECT CAST(COALESCE(
    (
        SELECT scan_id
        FROM findings
        WHERE asset_id = sqlc.arg(asset_id) AND fingerprint = sqlc.arg(fingerprint)
        ORDER BY scan_id
        LIMIT 1
    ),
    0
) AS INTEGER) AS first_seen_scan_id;

-- name: ListFindingsByScan :many
-- Findings of one scan, most severe first, with optional type/severity filters.
SELECT * FROM findings
WHERE scan_id = sqlc.arg(scan_id)
  AND (sqlc.narg(type) IS NULL OR type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR severity = sqlc.narg(severity))
ORDER BY
    CASE severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END,
    fingerprint;
