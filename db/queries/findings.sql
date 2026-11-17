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
    reachability,
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
    sqlc.narg(reachability),
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
-- the stored row, and state/reason carry the decision for the UI. A decision
-- whose expires_at is at or before the passed-in now counts as expired: the
-- finding is open again, and the expired flag keeps the stale decision visible.
SELECT
    f.id,
    f.scan_id,
    f.asset_id,
    f.type,
    f.fingerprint,
    f.occurrences,
    CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) AS severity,
    COALESCE(CAST(CASE
        WHEN f.type = 'license' THEN COALESCE(lpa.action, lpg.action)
    END AS TEXT), '') AS licence_policy,
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
    f.reachability,
    f.first_seen_scan_id,
    CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) AS status,
    fs.state AS state,
    fs.reason AS reason,
    fs.expires_at AS expires_at,
    CAST(CASE WHEN fs.id IS NOT NULL AND fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN 1 ELSE 0 END AS INTEGER) AS expired,
    f.created_at
FROM findings f
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
WHERE f.scan_id = sqlc.arg(scan_id)
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) = sqlc.narg(status))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
ORDER BY
    CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 1
        WHEN f.severity = 'critical' THEN 0
        WHEN f.severity = 'high' THEN 1
        WHEN f.severity = 'medium' THEN 2
        WHEN f.severity = 'low' THEN 3
        ELSE 4
    END,
    f.fingerprint
-- A nil window means no page: SQLite has no NULL LIMIT, so -1 stands in.
LIMIT CASE WHEN sqlc.narg(limit) IS NULL THEN -1 ELSE sqlc.narg(limit) END
OFFSET CASE WHEN sqlc.narg(offset) IS NULL THEN 0 ELSE sqlc.narg(offset) END;

-- name: CountFindingsByScanFiltered :one
-- Number of rows ListFindingsByScan returns for the same filters, ignoring
-- limit and offset. It is the scan findings list's total.
SELECT COUNT(*)
FROM findings f
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
WHERE f.scan_id = sqlc.arg(scan_id)
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) = sqlc.narg(status))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow');

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
    CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) AS severity,
    COALESCE(CAST(CASE
        WHEN f.type = 'license' THEN COALESCE(lpa.action, lpg.action)
    END AS TEXT), '') AS licence_policy,
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
    f.reachability,
    f.first_seen_scan_id,
    CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) AS status,
    fs.state AS state,
    fs.reason AS reason,
    fs.expires_at AS expires_at,
    CAST(CASE WHEN fs.id IS NOT NULL AND fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN 1 ELSE 0 END AS INTEGER) AS expired,
    f.created_at,
    -- The sort is a whitelisted key, not SQL: sort_key names a fixed ORDER BY
    -- expression and sort_order picks its direction. sqlc only generates
    -- arguments it sees in the SELECT list, so both travel as columns.
    CAST(sqlc.arg(sort) AS INTEGER) AS sort_key,
    CAST(sqlc.arg(order) AS INTEGER) AS sort_order
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
WHERE a.archived_at IS NULL
  AND s.status = 'succeeded'
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = f.asset_id AND s2.status = 'succeeded'
  )
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) = sqlc.narg(status))
  -- Text search (#148): a substring of the title, rule id, package or path.
  -- The caller sends %/_ pre-escaped, so the pattern is literal text; LIKE is
  -- case-insensitive for ASCII. The parentheses keep the ORs inside this filter
  -- and are also required by sqlc, which rejects two bare ESCAPE clauses.
  AND (sqlc.narg(query) IS NULL OR
       (f.title LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.rule_id LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.package_name LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.location LIKE sqlc.narg(query) ESCAPE '\'))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
ORDER BY
    -- A requested column sorts first. SQLite cannot parameterize ASC/DESC, so
    -- each direction is its own CASE; the unused direction is NULL for every
    -- row and does not constrain the order. sort_key only ever picks one of
    -- these fixed expressions, so no caller text reaches the SQL.
    CASE WHEN sort_order = 0 THEN CASE sort_key
        WHEN 1 THEN CASE severity
            WHEN 'critical' THEN 5
            WHEN 'high' THEN 4
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 2
            ELSE 1
        END
        WHEN 2 THEN lower(f.title)
        WHEN 3 THEN lower(f.package_name)
        WHEN 4 THEN lower(a.display_name)
        WHEN 5 THEN lower(f.type)
    END END ASC,
    CASE WHEN sort_order = 1 THEN CASE sort_key
        WHEN 1 THEN CASE severity
            WHEN 'critical' THEN 5
            WHEN 'high' THEN 4
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 2
            ELSE 1
        END
        WHEN 2 THEN lower(f.title)
        WHEN 3 THEN lower(f.package_name)
        WHEN 4 THEN lower(a.display_name)
        WHEN 5 THEN lower(f.type)
    END END DESC,
    -- No sort requested: the default order, most severe first. A requested
    -- column leaves these NULL for every row, so only the id tiebreaker applies.
    CASE WHEN sort_key = 0 THEN CASE severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END END ASC,
    CASE WHEN sort_key = 0 THEN f.asset_id END ASC,
    -- Stable tiebreaker: every page and direction ends in one deterministic order.
    f.id ASC
LIMIT CASE WHEN sqlc.narg(limit) IS NULL THEN -1 ELSE sqlc.narg(limit) END
OFFSET CASE WHEN sqlc.narg(offset) IS NULL THEN 0 ELSE sqlc.narg(offset) END;

-- name: CountLatestFindings :one
-- Number of rows ListLatestFindings returns for the same filters, ignoring
-- limit and offset. Grouped view counts groups in Go, not here.
SELECT COUNT(*)
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN finding_states fs
    ON fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
WHERE a.archived_at IS NULL
  AND s.status = 'succeeded'
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = f.asset_id AND s2.status = 'succeeded'
  )
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
  AND (sqlc.narg(type) IS NULL OR f.type = sqlc.narg(type))
  AND (sqlc.narg(severity) IS NULL OR CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) = sqlc.narg(severity))
  AND (sqlc.narg(status) IS NULL OR CAST(CASE
        WHEN fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) = sqlc.narg(status))
  -- Same text search as ListLatestFindings, so the total matches the page.
  AND (sqlc.narg(query) IS NULL OR
       (f.title LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.rule_id LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.package_name LIKE sqlc.narg(query) ESCAPE '\')
    OR (f.location LIKE sqlc.narg(query) ESCAPE '\'))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow');
