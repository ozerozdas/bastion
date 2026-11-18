-- +goose Up
-- Suppression rules (#181). An active rule writes ordinary finding_states rows,
-- so every list, count and report honours it; rule_ref says which rule wrote a
-- row and is cleared when the user decides that finding by hand. A NULL asset_id
-- applies the rule to every asset. An agent can only create a proposed rule.
CREATE TABLE finding_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER REFERENCES assets (id) ON DELETE CASCADE,
    finding_type TEXT CHECK (finding_type IS NULL OR finding_type IN ('vulnerability', 'secret', 'outdated', 'misconfig', 'license', 'sast')),
    rule_id      TEXT,
    package_name TEXT,
    path_glob    TEXT,
    state        TEXT NOT NULL CHECK (state IN ('ignored', 'accepted_risk', 'false_positive')),
    reason       TEXT NOT NULL,
    expires_at   TEXT,
    status       TEXT NOT NULL CHECK (status IN ('active', 'proposed')),
    created_by   TEXT NOT NULL CHECK (created_by IN ('user', 'agent')),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (finding_type IS NOT NULL OR rule_id IS NOT NULL OR package_name IS NOT NULL OR path_glob IS NOT NULL)
);

ALTER TABLE finding_states ADD COLUMN rule_ref INTEGER;

-- +goose Down
DELETE FROM finding_states WHERE rule_ref IS NOT NULL;
ALTER TABLE finding_states DROP COLUMN rule_ref;
DROP TABLE finding_rules;
