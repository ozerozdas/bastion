-- +goose Up
-- Fix plan pull requests (#47): the pull request bastion opened for one package
-- upgrade. A reloaded page used to offer "Open PR" again, so the plan read
-- attaches the recorded pull request instead. Only additive: a new table, no
-- rebuild of an existing one.
CREATE TABLE fix_plan_pull_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    ecosystem  TEXT    NOT NULL,
    package    TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    branch     TEXT    NOT NULL,
    number     INTEGER NOT NULL,
    url        TEXT    NOT NULL,
    manifest   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (asset_id, ecosystem, package, target)
);

CREATE INDEX idx_fix_plan_pull_requests_asset ON fix_plan_pull_requests (asset_id);

-- +goose Down
DROP TABLE fix_plan_pull_requests;
