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

-- name: SLAOverdueFindings :many
-- The latest open findings that are past their severity's threshold, most
-- overdue first, with the finish time of the scan that first saw them. The
-- whole ranking happens in SQL so the endpoint never decodes the fleet; the
-- caller asks for one row more than it returns to detect truncation.
--
-- The scope is the findings list's: the newest succeeded scan of every
-- non-archived asset, open findings only, a live finding_states decision
-- hides its finding, and licence "allow" findings are hidden. severity is the
-- effective severity, so a denied licence of low/medium/unknown severity ages
-- as high, and the threshold join leaves unknown severity out.
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
    f.cwe,
    f.reachability,
    f.first_seen_scan_id,
    CAST(CASE
        WHEN st.id IS NULL OR st.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN f.status
        ELSE 'ignored'
    END AS TEXT) AS status,
    COALESCE(st.state, '') AS state,
    st.reason AS reason,
    COALESCE(st.decided_by, '') AS decided_by,
    st.rule_ref AS rule_ref,
    st.expires_at AS expires_at,
    CAST(CASE WHEN st.id IS NOT NULL AND st.expires_at <= CAST(sqlc.arg(now) AS TEXT) THEN 1 ELSE 0 END AS INTEGER) AS expired,
    f.created_at,
    fs.finished_at AS first_seen_at,
    t.days AS threshold_days,
    CAST(julianday(CAST(sqlc.arg(now) AS TEXT)) - julianday(fs.finished_at) AS INTEGER) - t.days AS overdue_days
FROM findings f
JOIN scans fs ON fs.id = f.first_seen_scan_id
JOIN (
    SELECT s.asset_id, MAX(s.id) AS scan_id
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL AND s.status = 'succeeded'
    GROUP BY s.asset_id
) latest ON latest.asset_id = f.asset_id AND latest.scan_id = f.scan_id
LEFT JOIN finding_states st
    ON st.asset_id = f.asset_id AND st.fingerprint = f.fingerprint
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
JOIN sla_thresholds t
    ON t.severity = CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END
WHERE f.status = 'open'
  AND (st.id IS NULL OR st.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
  AND fs.finished_at IS NOT NULL
  -- The >= bound over-includes the exact threshold; the service recomputes
  -- the whole-day age and drops a finding that is not strictly past it.
  AND CAST(julianday(CAST(sqlc.arg(now) AS TEXT)) - julianday(fs.finished_at) AS INTEGER) >= t.days
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
ORDER BY overdue_days DESC, f.id ASC
LIMIT sqlc.arg(row_limit);

-- name: SLAFixedFindings :many
-- Findings that are gone from an asset's newest succeeded scan: each
-- fingerprint seen in some succeeded scan, with the finish time of the first
-- succeeded scan after its last appearance. A fingerprint that still appears
-- in the newest succeeded scan is open, not fixed, and is left out.
--
-- Candidates are bounded to fingerprints whose last appearance is followed by
-- a succeeded scan finished on or after window_start: a fix date before the
-- window cannot count, so the query need not aggregate the whole history. A
-- finding hidden by a live finding_states decision is not a fix.
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
      -- Keep the rows whose scan can belong to a fix inside the window: the
      -- last appearance itself finished in the window, or a later succeeded
      -- scan did. Dropping every row it would take to compute the last
      -- appearance is what keeps MAX(scan_id) below honest.
      AND (
          s.finished_at >= CAST(sqlc.arg(window_start) AS TEXT)
          OR EXISTS (
              SELECT 1
              FROM scans s2
              WHERE s2.asset_id = f.asset_id
                AND s2.status = 'succeeded'
                AND s2.id > f.scan_id
                AND s2.finished_at IS NOT NULL
                AND s2.finished_at >= CAST(sqlc.arg(window_start) AS TEXT)
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM finding_states st
          WHERE st.asset_id = f.asset_id AND st.fingerprint = f.fingerprint
            AND (st.expires_at IS NULL OR st.expires_at > CAST(sqlc.arg(now) AS TEXT))
      )
    GROUP BY f.asset_id, f.fingerprint
),
candidates AS (
    -- A group without a succeeded scan finished inside the window cannot be
    -- fixed inside it, so it is not a candidate at all.
    SELECT se.asset_id, se.fingerprint, se.first_seen_scan_id, se.last_seen_scan_id
    FROM seen se
    WHERE EXISTS (
        SELECT 1
        FROM scans s2
        WHERE s2.asset_id = se.asset_id
          AND s2.status = 'succeeded'
          AND s2.id > se.last_seen_scan_id
          AND s2.finished_at IS NOT NULL
          AND s2.finished_at >= CAST(sqlc.arg(window_start) AS TEXT)
    )
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
    FROM candidates se
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
  AND ff.finished_at >= CAST(sqlc.arg(window_start) AS TEXT)
ORDER BY fx.asset_id, fx.fingerprint;
