-- name: CreateScan :one
INSERT INTO scans (asset_id, target_ref, status, "trigger", started_at)
VALUES (
    sqlc.arg(asset_id),
    sqlc.narg(target_ref),
    sqlc.arg(status),
    sqlc.arg(trigger),
    sqlc.arg(started_at)
)
RETURNING *;

-- name: GetScan :one
SELECT * FROM scans WHERE id = sqlc.arg(id);

-- name: MarkScanRunning :exec
-- Keep the start time a caller has already recorded; set it on the first
-- transition to running.
UPDATE scans
SET status = 'running',
    started_at = COALESCE(started_at, sqlc.arg(started_at))
WHERE id = sqlc.arg(id);

-- name: FinishScan :exec
-- Record the final state of a scan. An empty target_ref keeps the value the
-- scan was created with.
UPDATE scans
SET status = sqlc.arg(status),
    finished_at = sqlc.arg(finished_at),
    error = sqlc.narg(error),
    target_ref = COALESCE(sqlc.narg(target_ref), target_ref)
WHERE id = sqlc.arg(id);

-- name: ListScansByAsset :many
-- Newest first: ids increase with time, so ordering by id is stable even when
-- two scans share a started_at.
SELECT * FROM scans WHERE asset_id = sqlc.arg(asset_id) ORDER BY id DESC LIMIT sqlc.arg(limit);

-- name: GetPreviousSucceededScan :one
-- The newest succeeded scan of one asset older than the given scan: the default
-- baseline of a diff. sql.ErrNoRows means the given scan is the asset's first
-- succeeded one, so there is nothing to compare against.
SELECT * FROM scans
WHERE asset_id = sqlc.arg(asset_id)
  AND status = 'succeeded'
  AND id < sqlc.arg(id)
ORDER BY id DESC
LIMIT 1;

-- name: FailUnfinishedScans :exec
-- Startup recovery: a scan still queued or running when this process starts
-- was cut short by the previous process exiting, so it can never finish.
UPDATE scans
SET status = 'failed',
    finished_at = sqlc.arg(finished_at),
    error = sqlc.arg(error)
WHERE status IN ('queued', 'running');

-- name: ListScannerRunsByScan :many
-- Scanner runs of one scan in execution order. Reading a finished scan back
-- (CLI output, reports) needs the rows InsertScannerRun wrote.
SELECT * FROM scanner_runs
WHERE scan_id = sqlc.arg(scan_id)
ORDER BY id;

-- name: InsertScannerRun :exec
INSERT INTO scanner_runs (scan_id, scanner, scanner_version, db_version, status, duration_ms, error, raw_path)
VALUES (
    sqlc.arg(scan_id),
    sqlc.arg(scanner),
    sqlc.narg(scanner_version),
    sqlc.narg(db_version),
    sqlc.arg(status),
    sqlc.narg(duration_ms),
    sqlc.narg(error),
    sqlc.narg(raw_path)
);

-- name: ListScans :many
-- Newest first, optionally narrowed to one asset. Ids increase with time, so
-- ordering by id is stable even when two scans share a started_at. The counts
-- are the findings the scan recorded after the licence policy (#39): an
-- allow-listed licence is hidden and a deny-listed one counts as high. They
-- come from one grouped read over the listed scans (see idx_findings_scan).
WITH scan_counts AS (
    SELECT
        f.scan_id,
        CAST(SUM(CASE WHEN CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END = 'critical' THEN 1 ELSE 0 END) AS INTEGER) AS critical_count,
        CAST(SUM(CASE WHEN CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END = 'high' THEN 1 ELSE 0 END) AS INTEGER) AS high_count,
        CAST(SUM(CASE WHEN CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END = 'medium' THEN 1 ELSE 0 END) AS INTEGER) AS medium_count,
        CAST(SUM(CASE WHEN CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END = 'low' THEN 1 ELSE 0 END) AS INTEGER) AS low_count,
        CAST(SUM(CASE WHEN CASE
                 WHEN f.type = 'license'
                      AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                      AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
                 ELSE f.severity
             END = 'unknown' THEN 1 ELSE 0 END) AS INTEGER) AS unknown_count
    FROM findings f
    LEFT JOIN licence_policy lpa
        ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
    LEFT JOIN licence_policy lpg
        ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
    WHERE NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow')
    GROUP BY f.scan_id
)
SELECT
    sqlc.embed(s),
    CAST(COALESCE(sc.critical_count, 0) AS INTEGER) AS critical_count,
    CAST(COALESCE(sc.high_count, 0) AS INTEGER) AS high_count,
    CAST(COALESCE(sc.medium_count, 0) AS INTEGER) AS medium_count,
    CAST(COALESCE(sc.low_count, 0) AS INTEGER) AS low_count,
    CAST(COALESCE(sc.unknown_count, 0) AS INTEGER) AS unknown_count
FROM scans s
LEFT JOIN scan_counts sc ON sc.scan_id = s.id
WHERE (sqlc.narg(asset_id) IS NULL OR s.asset_id = sqlc.narg(asset_id))
ORDER BY s.id DESC
-- A nil window means no page: SQLite has no NULL LIMIT, so -1 stands in.
LIMIT CASE WHEN sqlc.narg(limit) IS NULL THEN -1 ELSE sqlc.narg(limit) END
OFFSET CASE WHEN sqlc.narg(offset) IS NULL THEN 0 ELSE sqlc.narg(offset) END;

-- name: CountScans :one
-- Number of scans ListScans returns for the same asset filter, ignoring limit
-- and offset.
SELECT COUNT(*)
FROM scans s
WHERE (sqlc.narg(asset_id) IS NULL OR s.asset_id = sqlc.narg(asset_id));

-- name: CountFindingsByScan :one
-- Every finding one scan recorded, per severity, after the licence policy
-- (#39): the single-scan read shows the same counts as the scan list. A scan
-- that recorded nothing is all zeros.
SELECT
    CAST(COALESCE(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'critical' THEN 1 ELSE 0 END), 0) AS INTEGER) AS critical_count,
    CAST(COALESCE(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'high' THEN 1 ELSE 0 END), 0) AS INTEGER) AS high_count,
    CAST(COALESCE(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'medium' THEN 1 ELSE 0 END), 0) AS INTEGER) AS medium_count,
    CAST(COALESCE(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'low' THEN 1 ELSE 0 END), 0) AS INTEGER) AS low_count,
    CAST(COALESCE(SUM(CASE WHEN CASE
             WHEN f.type = 'license'
                  AND COALESCE(lpa.action, lpg.action, '') = 'deny'
                  AND f.severity IN ('low', 'medium', 'unknown') THEN 'high'
             ELSE f.severity
         END = 'unknown' THEN 1 ELSE 0 END), 0) AS INTEGER) AS unknown_count
FROM findings f
LEFT JOIN licence_policy lpa
    ON lpa.asset_id = f.asset_id AND lpa.licence = lower(f.rule_id)
LEFT JOIN licence_policy lpg
    ON lpg.asset_id IS NULL AND lpg.licence = lower(f.rule_id)
WHERE f.scan_id = sqlc.arg(scan_id)
  AND NOT (f.type = 'license' AND COALESCE(lpa.action, lpg.action, '') = 'allow');
