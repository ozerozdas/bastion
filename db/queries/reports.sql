-- Dashboard aggregates (PROJECT_SPEC.md sections 6 and 7.1). Every number counts only
-- open findings of each non-archived asset's most recent succeeded scan: a
-- failed or running scan does not shadow the last complete report, and a
-- finding_states decision hides its finding (status is computed the same way
-- as in findings.sql) until its optional expires_at passes (#32). Ignore
-- decisions are keyed on (asset_id, fingerprint), so they also apply
-- retroactively to older scans in the trend.

-- name: ReportTotalsBySeverity :many
-- Open findings per severity across the fleet. Severities without findings
-- are absent; the caller fills them with zero.
SELECT
    CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT) AS severity,
    COUNT(*) AS finding_count
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
  AND f.status = 'open'
  AND (fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
GROUP BY CAST(CASE
        WHEN f.type = 'license'
             AND COALESCE(lpa.action, lpg.action) = 'deny'
             AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
        ELSE f.severity
    END AS TEXT)
ORDER BY severity;

-- name: ReportTotalsByType :many
-- Open findings per type across the fleet, with the same scope as
-- ReportTotalsBySeverity.
SELECT f.type, COUNT(*) AS finding_count
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
  AND f.status = 'open'
  AND (fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
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
    CAST(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action) = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'critical' THEN 1 ELSE 0 END) AS INTEGER) AS critical,
    CAST(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action) = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'high' THEN 1 ELSE 0 END) AS INTEGER) AS high,
    CAST(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action) = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'medium' THEN 1 ELSE 0 END) AS INTEGER) AS medium,
    CAST(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action) = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'low' THEN 1 ELSE 0 END) AS INTEGER) AS low,
    CAST(SUM(CASE CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action) = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END
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
  AND f.status = 'open'
  AND (fs.id IS NULL OR fs.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
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
LEFT JOIN (
    SELECT
        f.id,
        f.scan_id,
        f.asset_id,
        f.fingerprint,
        f.type,
        f.status,
        COALESCE(lpa.action, lpg.action, '') AS licence_action,
        CASE
            WHEN f.type = 'license'
                 AND COALESCE(lpa.action, lpg.action) = 'deny'
                 AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
            ELSE f.severity
        END AS effective_severity
    FROM findings f
    LEFT JOIN licence_policy lpa
        ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
    LEFT JOIN licence_policy lpg
        ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
) f
    ON f.scan_id = r.scan_id
   AND f.status = 'open'
   AND f.effective_severity IN ('critical', 'high')
   AND NOT (f.type = 'license' AND f.licence_action = 'allow')
   AND NOT EXISTS (
       SELECT 1
       FROM finding_states fs
       WHERE fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
         AND (fs.expires_at IS NULL OR fs.expires_at > CAST(sqlc.arg(now) AS TEXT))
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

-- name: CVEInsightsFindings :many
-- Latest open findings whose rule id is the requested CVE or GHSA id, with the
-- asset they belong to and the finish time of the scan that first saw them.
-- The scope mirrors ListLatestFindings: the newest succeeded scan of every
-- non-archived asset, open findings only (a finding_states decision hides its
-- finding until its expiry), and licence "allow" findings stay hidden. Aliases
-- are merge-only and never stored, so the rule id is the only match.
SELECT
    f.id,
    f.asset_id,
    a.display_name,
    a.kind,
    f.severity,
    f.package_name,
    f.package_version,
    f.fixed_version,
    f.rule_id,
    fs.finished_at AS first_seen_at
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN scans fs ON fs.id = f.first_seen_scan_id
LEFT JOIN finding_states st
    ON st.asset_id = f.asset_id AND st.fingerprint = f.fingerprint
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
  AND f.status = 'open'
  AND (st.id IS NULL OR st.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
  AND lower(COALESCE(f.rule_id, '')) = lower(CAST(sqlc.arg(cve) AS TEXT))
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
ORDER BY a.display_name, f.package_name, f.id;

-- name: ReportSeverityTrend :many
-- One point per asset and day that has a succeeded scan since the window start.
-- The point counts the open findings of that day's last succeeded scan by
-- effective severity. Ignore decisions hide a finding in every scan that
-- carries its fingerprint, exactly like ReportTrendScans, and the scope is the
-- findings list's: non-archived assets only, licence "allow" findings hidden.
WITH ranked AS (
    SELECT
        s.id AS scan_id,
        s.asset_id,
        CAST(date(s.finished_at) AS TEXT) AS scan_date,
        ROW_NUMBER() OVER (
            PARTITION BY s.asset_id, CAST(date(s.finished_at) AS TEXT)
            ORDER BY s.id DESC
        ) AS day_rank
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL
      AND s.status = 'succeeded'
      AND s.finished_at IS NOT NULL
      AND CAST(date(s.finished_at) AS TEXT) >= CAST(sqlc.arg(since) AS TEXT)
),
counted AS (
    SELECT
        f.scan_id,
        f.asset_id,
        f.fingerprint,
        f.type,
        COALESCE(lpa.action, lpg.action, '') AS licence_action,
        CASE
            WHEN f.type = 'license'
                 AND COALESCE(lpa.action, lpg.action) = 'deny'
                 AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
            ELSE f.severity
        END AS effective_severity
    FROM findings f
    -- Only the scans that will become points: without this join the CTE reads
    -- every finding in the database instead of the window's scans.
    JOIN ranked r ON r.scan_id = f.scan_id
    LEFT JOIN licence_policy lpa
        ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
    LEFT JOIN licence_policy lpg
        ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
    WHERE f.status = 'open'
      AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
      AND NOT EXISTS (
          SELECT 1
          FROM finding_states fs
          WHERE fs.asset_id = f.asset_id AND fs.fingerprint = f.fingerprint
            AND (fs.expires_at IS NULL OR fs.expires_at > CAST(sqlc.arg(now) AS TEXT))
      )
)
SELECT
    r.asset_id,
    a.display_name,
    r.scan_date,
    CAST(SUM(CASE WHEN c.effective_severity = 'critical' THEN 1 ELSE 0 END) AS INTEGER) AS critical,
    CAST(SUM(CASE WHEN c.effective_severity = 'high' THEN 1 ELSE 0 END) AS INTEGER) AS high,
    CAST(SUM(CASE WHEN c.effective_severity = 'medium' THEN 1 ELSE 0 END) AS INTEGER) AS medium,
    CAST(SUM(CASE WHEN c.effective_severity = 'low' THEN 1 ELSE 0 END) AS INTEGER) AS low,
    CAST(SUM(CASE WHEN c.effective_severity = 'unknown' THEN 1 ELSE 0 END) AS INTEGER) AS unknown
FROM ranked r
JOIN assets a ON a.id = r.asset_id
LEFT JOIN counted c
    ON c.scan_id = r.scan_id AND c.asset_id = r.asset_id
WHERE r.day_rank = 1
  AND (sqlc.narg(asset_id) IS NULL OR r.asset_id = sqlc.narg(asset_id))
GROUP BY r.asset_id, a.display_name, r.scan_date
ORDER BY a.display_name, r.asset_id, r.scan_date;

-- name: RuntimeEOLFindings :many
-- Latest open end-of-life findings, one row per asset and runtime. The scope
-- mirrors ListLatestFindings: the newest succeeded scan of every non-archived
-- asset, open findings only (a finding_states decision hides its finding until
-- its expiry). The eol scanner sets rule_id "eol" and puts the end-of-life
-- date in the description.
SELECT
    f.asset_id,
    a.display_name,
    f.package_name,
    f.package_version,
    f.ecosystem,
    f.fixed_version,
    f.description
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN finding_states st
    ON st.asset_id = f.asset_id AND st.fingerprint = f.fingerprint
WHERE a.archived_at IS NULL
  AND s.status = 'succeeded'
  AND s.id = (
      SELECT MAX(s2.id)
      FROM scans s2
      WHERE s2.asset_id = f.asset_id AND s2.status = 'succeeded'
  )
  AND f.status = 'open'
  AND (st.id IS NULL OR st.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND f.rule_id = 'eol'
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
ORDER BY f.package_name, f.package_version, a.display_name, f.asset_id;

-- name: ReportLicenseFindings :many
-- Latest open licence findings with the effective allow/deny rule (#39)
-- resolved per asset over the global one. Unlike ListLatestFindings, allow
-- findings are kept: this report exists to show the whole licence inventory.
-- The rest of the scope is the findings list's: non-archived assets, their
-- newest succeeded scan, and ignore decisions applied until they expire.
SELECT
    COALESCE(f.rule_id, '') AS license,
    CAST(COALESCE(lpa.action, lpg.action, 'none') AS TEXT) AS policy,
    f.package_name,
    f.package_version,
    f.ecosystem,
    f.asset_id,
    a.display_name
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN finding_states st
    ON st.asset_id = f.asset_id AND st.fingerprint = f.fingerprint
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
  AND f.type = 'license'
  AND f.status = 'open'
  AND (st.id IS NULL OR st.expires_at <= CAST(sqlc.arg(now) AS TEXT))
  AND (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
ORDER BY lower(COALESCE(f.rule_id, '')), a.display_name, f.package_name;

-- name: ReportCIHistory :many
-- CLI- and API-triggered scans, newest first, with the raw severity counts of
-- what each scan recorded. Unlike the dashboard counts, these are not
-- ignore-filtered and no licence policy applies: the history reports what the
-- CI run produced, not today's view of it.
WITH selected AS (
    SELECT s.id, s.asset_id, a.display_name, s."trigger", s.status, s.started_at, s.finished_at
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL
      AND s."trigger" IN ('cli', 'api')
      AND (sqlc.narg(asset_id) IS NULL OR s.asset_id = sqlc.narg(asset_id))
    ORDER BY s.id DESC
    LIMIT sqlc.arg(run_limit)
),
counts AS (
    -- One grouped pass over the selected scans' findings, not one correlated
    -- subquery per severity.
    SELECT
        f.scan_id,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low,
        SUM(CASE WHEN f.severity = 'unknown' THEN 1 ELSE 0 END) AS unknown
    FROM findings f
    WHERE f.scan_id IN (SELECT id FROM selected)
    GROUP BY f.scan_id
)
SELECT
    s.id AS scan_id,
    s.asset_id,
    s.display_name,
    s."trigger",
    s.status,
    s.started_at,
    s.finished_at,
    CAST(COALESCE(c.critical, 0) AS INTEGER) AS critical,
    CAST(COALESCE(c.high, 0) AS INTEGER) AS high,
    CAST(COALESCE(c.medium, 0) AS INTEGER) AS medium,
    CAST(COALESCE(c.low, 0) AS INTEGER) AS low,
    CAST(COALESCE(c.unknown, 0) AS INTEGER) AS unknown
FROM selected s
LEFT JOIN counts c ON c.scan_id = s.id
ORDER BY s.id DESC;

-- name: ReportCIScannerRuns :many
-- The scanner runs of the newest CLI/API scans in the same order-limited set
-- ReportCIHistory returns, so the history can name each scanner and its
-- outcome.
SELECT sr.scan_id, sr.scanner, sr.status
FROM scanner_runs sr
WHERE sr.scan_id IN (
    SELECT s.id
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE a.archived_at IS NULL
      AND s."trigger" IN ('cli', 'api')
      AND (sqlc.narg(asset_id) IS NULL OR s.asset_id = sqlc.narg(asset_id))
    ORDER BY s.id DESC
    LIMIT sqlc.arg(run_limit)
)
ORDER BY sr.scan_id, sr.scanner;
