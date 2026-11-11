-- Dashboard aggregates (PROJECT_SPEC.md §6, §7.1). Every number counts only
-- open findings of each non-archived asset's most recent succeeded scan: a
-- failed or running scan does not shadow the last complete report, and a
-- finding_states decision hides its finding (status is computed the same way
-- as in findings.sql). Ignore decisions are keyed on (asset_id, fingerprint),
-- so they also apply retroactively to older scans in the trend.

-- name: ReportTotalsBySeverity :many
-- Open findings per severity across the fleet. Severities without findings
-- are absent; the caller fills them with zero.
SELECT f.severity, COUNT(*) AS finding_count
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
  AND f.status = 'open'
  AND fs.id IS NULL
GROUP BY f.severity
ORDER BY f.severity;

-- name: ReportTotalsByType :many
-- Open findings per type across the fleet, with the same scope as
-- ReportTotalsBySeverity.
SELECT f.type, COUNT(*) AS finding_count
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
  AND f.status = 'open'
  AND fs.id IS NULL
GROUP BY f.type
ORDER BY f.type;

-- name: ReportTopAssets :many
-- The five riskiest assets: score = critical*1000 + high*100 + medium*10 + low,
-- counted over the same open findings as the totals. Assets whose open findings
-- are all "unknown" severity score 0 and are left out rather than ranked.
SELECT
    f.asset_id,
    a.display_name,
    a.kind,
    CAST(SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS INTEGER) AS critical,
    CAST(SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS INTEGER) AS high,
    CAST(SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS INTEGER) AS medium,
    CAST(SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS INTEGER) AS low,
    CAST(SUM(CASE f.severity
                 WHEN 'critical' THEN 1000
                 WHEN 'high' THEN 100
                 WHEN 'medium' THEN 10
                 WHEN 'low' THEN 1
                 ELSE 0
             END) AS INTEGER) AS score
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
  AND f.status = 'open'
  AND fs.id IS NULL
GROUP BY f.asset_id
HAVING score > 0
ORDER BY score DESC, a.display_name, f.asset_id
LIMIT 5;

-- name: ReportTrendScans :many
-- The last ten succeeded scans of every non-archived asset, with the number of
-- open critical+high findings each scan reported. Oldest scan first, so the
-- caller can plot the series directly. Ignore decisions hide a finding in every
-- scan that carries its fingerprint, including scans older than the decision.
WITH ranked AS (
    SELECT
        s.id AS scan_id,
        s.asset_id,
        s.finished_at,
        ROW_NUMBER() OVER (PARTITION BY s.asset_id ORDER BY s.id DESC) AS scan_rank
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL AND s.status = 'succeeded'
)
SELECT
    r.asset_id,
    r.scan_id,
    r.finished_at,
    COUNT(f.id) AS critical_high_open
FROM ranked r
LEFT JOIN findings f
    ON f.scan_id = r.scan_id
   AND f.status = 'open'
   AND f.severity IN ('critical', 'high')
   AND NOT EXISTS (
       SELECT 1
       FROM finding_states fs
       WHERE fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
   )
WHERE r.scan_rank <= 10
GROUP BY r.asset_id, r.scan_id, r.finished_at
ORDER BY r.asset_id, r.scan_id;

-- name: ReportLastScans :many
-- The newest scan of every non-archived asset that has one, whatever its
-- status: a failed last scan is exactly what the dashboard must show.
SELECT s.asset_id, a.display_name, s.id AS scan_id, s.status, s.finished_at
FROM scans s
JOIN assets a ON a.id = s.asset_id
WHERE a.archived_at IS NULL
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = s.asset_id
  )
ORDER BY s.asset_id;
