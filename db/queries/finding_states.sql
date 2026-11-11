-- name: UpsertFindingState :exec
-- Record a user decision for one fingerprint of one asset (PROJECT_SPEC.md
-- finding_states).
-- Re-deciding replaces the previous state and reason; the decision survives
-- later scans because it is keyed on (asset_id, fingerprint).
INSERT INTO finding_states (asset_id, fingerprint, state, reason)
VALUES (
    sqlc.arg(asset_id),
    sqlc.arg(fingerprint),
    sqlc.arg(state),
    sqlc.narg(reason)
)
ON CONFLICT (asset_id, fingerprint) DO UPDATE SET
    state  = excluded.state,
    reason = excluded.reason;

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
