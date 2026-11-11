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

-- name: FailUnfinishedScans :exec
-- Startup recovery: a scan still queued or running when this process starts
-- was cut short by the previous process exiting, so it can never finish.
UPDATE scans
SET status = 'failed',
    finished_at = sqlc.arg(finished_at),
    error = sqlc.arg(error)
WHERE status IN ('queued', 'running');

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
