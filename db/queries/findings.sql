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
    scanners,
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
    sqlc.arg(scanners),
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
-- Findings of one scan, most severe first, with optional type/severity/status
-- filters. status is the effective status: a finding_states row for the same
-- (asset_id, fingerprint) reports the finding as 'ignored' without rewriting
-- the stored row, and state/reason carry the decision for the UI.
SELECT
    f.id,
    f.scan_id,
    f.asset_id,
    f.type,
    f.fingerprint,
    f.occurrences,
    f.severity,
    f.title,
    f.rule_id,
    f.package_name,
    f.package_version,
    f.fixed_version,
    f.ecosystem,
    f.location,
    f.cvss,
    f.epss,
    f.description,
    f.references_json,
    f.scanner,
    f.scanners,
    f.first_seen_scan_id,
    CAST(CASE WHEN fs.id IS NULL THEN f.status ELSE 'ignored' END AS TEXT) AS status,
    fs.state AS state,
    fs.reason AS reason,
    f.created_at
FROM findings f
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
WHERE f.scan_id = sqlc.arg(scan_id)
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR f.severity = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE WHEN fs.id IS NULL THEN f.status ELSE 'ignored' END AS TEXT) = sqlc.narg(status))
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END,
    f.fingerprint;

-- name: ListLatestFindings :many
-- Findings of the most recent succeeded scan of every non-archived asset, so
-- the UI shows the current state of the fleet. Failed, canceled and running
-- scans are skipped: when the newest scan failed, its asset still reports the
-- previous succeeded scan. Filters and the effective status match
-- ListFindingsByScan.
SELECT
    f.id,
    f.scan_id,
    f.asset_id,
    f.type,
    f.fingerprint,
    f.occurrences,
    f.severity,
    f.title,
    f.rule_id,
    f.package_name,
    f.package_version,
    f.fixed_version,
    f.ecosystem,
    f.location,
    f.cvss,
    f.epss,
    f.description,
    f.references_json,
    f.scanner,
    f.scanners,
    f.first_seen_scan_id,
    CAST(CASE WHEN fs.id IS NULL THEN f.status ELSE 'ignored' END AS TEXT) AS status,
    fs.state AS state,
    fs.reason AS reason,
    f.created_at
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
WHERE a.archived_at IS NULL
  AND s.status = 'succeeded'
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = f.asset_id AND s2.status = 'succeeded'
  )
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR f.severity = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE WHEN fs.id IS NULL THEN f.status ELSE 'ignored' END AS TEXT) = sqlc.narg(status))
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END,
    f.asset_id,
    f.fingerprint;
