-- name: UpsertFindingState :exec
-- Record a user decision for one fingerprint of one asset (PROJECT_SPEC.md
-- finding_states).
-- Re-deciding replaces the previous state, reason and expiry; the decision
-- survives later scans because it is keyed on (asset_id, fingerprint). A NULL
-- expires_at keeps the decision until it is cleared (#32).
INSERT INTO finding_states (asset_id, fingerprint, state, reason, expires_at)
VALUES (
    sqlc.arg(asset_id),
    sqlc.arg(fingerprint),
    sqlc.arg(state),
    sqlc.narg(reason),
    sqlc.narg(expires_at)
)
ON CONFLICT (asset_id, fingerprint) DO UPDATE SET
    state      = excluded.state,
    reason     = excluded.reason,
    expires_at = excluded.expires_at;

-- name: DeleteFindingState :exec
-- Remove the decision, so the finding shows its stored status again.
DELETE FROM finding_states
WHERE asset_id = sqlc.arg(asset_id) AND fingerprint = sqlc.arg(fingerprint);

-- name: GetFindingState :one
SELECT * FROM finding_states
WHERE asset_id = sqlc.arg(asset_id) AND fingerprint = sqlc.arg(fingerprint);

-- name: ListFindingStatesByAsset :many
SELECT * FROM finding_states
WHERE asset_id = sqlc.arg(asset_id)
ORDER BY fingerprint;

-- name: ListKnownFingerprints :many
-- Fingerprints of the asset that already appear in its findings, across every
-- scan. A bulk decision may only name findings the asset actually has, so the
-- store checks the whole list before it writes anything.
SELECT DISTINCT fingerprint FROM findings
WHERE asset_id = sqlc.arg(asset_id)
  AND fingerprint IN (sqlc.slice('fingerprints'))
ORDER BY fingerprint;
