-- SLA thresholds and the fixed-finding side of the SLA report (#190).

-- name: ListSLAThresholds :many
-- Every severity's allowed age in days. The migration seeds all four rows, so
-- a mature database always returns the complete set.
SELECT severity, days
FROM sla_thresholds
ORDER BY severity;

-- name: UpsertSLAThreshold :exec
INSERT INTO sla_thresholds (severity, days)
VALUES (sqlc.arg(severity), sqlc.arg(days))
ON CONFLICT (severity) DO UPDATE SET days = excluded.days;

-- name: SLAFirstSeen :many
-- The finish time of the scan that first saw each open finding of every
-- non-archived asset's newest succeeded scan. The service joins it onto the
-- findings list to age a finding without a query per row; the ignore scope is
-- not repeated here because the caller only asks for findings it already has.
SELECT f.id AS finding_id, fs.finished_at AS first_seen_at
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN scans fs ON fs.id = f.first_seen_scan_id
WHERE a.archived_at IS NULL
  AND s.status = 'succeeded'
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = f.asset_id AND s2.status = 'succeeded'
  )
  AND f.status = 'open'
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id));

-- name: SLAFixedFindings :many
-- Findings that are gone from an asset's newest succeeded scan: each
-- fingerprint seen in some succeeded scan, with the finish time of the first
-- succeeded scan after its last appearance. A fingerprint that still appears
-- in the newest succeeded scan is open, not fixed, and is left out.
WITH latest AS (
    SELECT s.asset_id, MAX(s.id) AS scan_id
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL AND s.status = 'succeeded'
    GROUP BY s.asset_id
),
seen AS (
    SELECT
        f.asset_id,
        f.fingerprint,
        MIN(f.first_seen_scan_id) AS first_seen_scan_id,
        MAX(f.scan_id) AS last_seen_scan_id
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN assets a ON a.id = f.asset_id
    WHERE a.archived_at IS NULL
      AND s.status = 'succeeded'
      AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
    GROUP BY f.asset_id, f.fingerprint
),
fixed AS (
    SELECT
        se.asset_id,
        se.fingerprint,
        se.first_seen_scan_id,
        (
            SELECT MIN(s2.id)
            FROM scans s2
            WHERE s2.asset_id = se.asset_id
              AND s2.status = 'succeeded'
              AND s2.id > se.last_seen_scan_id
        ) AS fix_scan_id
    FROM seen se
    JOIN latest l ON l.asset_id = se.asset_id
    WHERE se.last_seen_scan_id < l.scan_id
)
SELECT
    fx.asset_id,
    fx.fingerprint,
    fs.finished_at AS first_seen_at,
    ff.finished_at AS fixed_at
FROM fixed fx
JOIN scans fs ON fs.id = fx.first_seen_scan_id
JOIN scans ff ON ff.id = fx.fix_scan_id
WHERE fs.finished_at IS NOT NULL
  AND ff.finished_at IS NOT NULL
ORDER BY fx.asset_id, fx.fingerprint;
