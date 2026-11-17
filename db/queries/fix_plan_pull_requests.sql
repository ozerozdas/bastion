-- name: UpsertFixPlanPullRequest :exec
INSERT INTO fix_plan_pull_requests (
    asset_id,
    ecosystem,
    package,
    target,
    branch,
    number,
    url,
    manifest,
    created_at
)
VALUES (
    sqlc.arg(asset_id),
    sqlc.arg(ecosystem),
    sqlc.arg(package),
    sqlc.arg(target),
    sqlc.arg(branch),
    sqlc.arg(number),
    sqlc.arg(url),
    sqlc.arg(manifest),
    sqlc.arg(created_at)
)
ON CONFLICT (asset_id, ecosystem, package, target) DO UPDATE SET
    branch = excluded.branch,
    number = excluded.number,
    url = excluded.url,
    manifest = excluded.manifest;

-- name: ListFixPlanPullRequests :many
-- Every pull request bastion opened for one asset, oldest first.
SELECT *
FROM fix_plan_pull_requests
WHERE asset_id = sqlc.arg(asset_id)
ORDER BY id;

-- name: DeleteFixPlanPullRequest :exec
DELETE FROM fix_plan_pull_requests WHERE id = sqlc.arg(id);
