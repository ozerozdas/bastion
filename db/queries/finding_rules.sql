-- name: CreateFindingRule :one
INSERT INTO finding_rules (asset_id, finding_type, rule_id, package_name, path_glob, state, reason, expires_at, status, created_by)
VALUES (
    sqlc.narg(asset_id),
    sqlc.narg(finding_type),
    sqlc.narg(rule_id),
    sqlc.narg(package_name),
    sqlc.narg(path_glob),
    sqlc.arg(state),
    sqlc.arg(reason),
    sqlc.narg(expires_at),
    sqlc.arg(status),
    sqlc.arg(created_by)
)
RETURNING id;

-- name: ListFindingRules :many
-- Every rule with the number of findings it currently closes.
SELECT
    r.id, r.asset_id, r.finding_type, r.rule_id, r.package_name, r.path_glob,
    r.state, r.reason, r.expires_at, r.status, r.created_by, r.created_at,
    CAST((
        SELECT COUNT(*) FROM finding_states fs
        WHERE fs.rule_ref = r.id AND (fs.expires_at IS NULL OR fs.expires_at > CAST(sqlc.arg(now) AS TEXT))
    ) AS INTEGER) AS matched
FROM finding_rules r
ORDER BY r.status DESC, r.id DESC;

-- name: ActivateFindingRule :execrows
UPDATE finding_rules SET status = 'active'
WHERE id = sqlc.arg(id) AND status = 'proposed';

-- name: DeleteFindingRule :execrows
DELETE FROM finding_rules WHERE id = sqlc.arg(id);

-- name: DeleteFindingStatesByRule :exec
DELETE FROM finding_states WHERE rule_ref = sqlc.arg(rule_ref);

-- name: ApplyFindingRules :exec
-- Close the findings active rules match, for one asset or for all of them. An
-- existing decision wins unless it has expired. Malware is never closed by a rule, and a secret only
-- by a rule that names the secret type.
INSERT INTO finding_states (asset_id, fingerprint, state, reason, expires_at, decided_by, rule_ref)
SELECT f.asset_id, f.fingerprint, r.state, r.reason, r.expires_at, 'user', r.id
FROM findings f
JOIN finding_rules r
    ON r.status = 'active' AND (r.asset_id IS NULL OR r.asset_id = f.asset_id)
WHERE (sqlc.narg(asset_id) IS NULL OR f.asset_id = sqlc.narg(asset_id))
  AND f.type <> 'malware'
  AND (f.type <> 'secret' OR r.finding_type = 'secret')
  AND (r.finding_type IS NULL OR f.type = r.finding_type)
  AND (r.rule_id IS NULL OR f.rule_id = r.rule_id)
  AND (r.package_name IS NULL OR f.package_name = r.package_name)
  AND (r.path_glob IS NULL OR COALESCE(f.location, '') GLOB r.path_glob)
  AND (r.expires_at IS NULL OR r.expires_at > CAST(sqlc.arg(now) AS TEXT))
ORDER BY r.id
ON CONFLICT (asset_id, fingerprint) DO UPDATE SET
    state      = excluded.state,
    reason     = excluded.reason,
    expires_at = excluded.expires_at,
    decided_by = excluded.decided_by,
    rule_ref   = excluded.rule_ref
WHERE finding_states.expires_at IS NOT NULL
  AND finding_states.expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
