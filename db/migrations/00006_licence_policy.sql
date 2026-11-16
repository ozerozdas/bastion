-- +goose Up
-- Licence policy (#39): an allow/deny decision per licence, either global
-- (asset_id NULL) or for one asset. The policy is applied at read time, so a
-- change immediately affects every stored finding without rewriting scans.
--
-- licence is stored normalized to lower case, because Trivy reports the same
-- SPDX id with inconsistent case and SQLite's UNIQUE is case-sensitive.
CREATE TABLE licence_policy (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER REFERENCES assets (id) ON DELETE CASCADE,
    licence    TEXT    NOT NULL CHECK (length(licence) BETWEEN 1 AND 128),
    action     TEXT    NOT NULL CHECK (action IN ('allow', 'deny')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (asset_id, licence)
);

-- SQLite treats NULLs as distinct, so the table constraint above does not stop
-- two global rows for the same licence; the partial index does.
CREATE UNIQUE INDEX idx_licence_policy_global ON licence_policy (licence)
    WHERE asset_id IS NULL;
CREATE INDEX idx_licence_policy_asset ON licence_policy (asset_id);

-- +goose Down
DROP INDEX idx_licence_policy_asset;
DROP INDEX idx_licence_policy_global;
DROP TABLE licence_policy;
