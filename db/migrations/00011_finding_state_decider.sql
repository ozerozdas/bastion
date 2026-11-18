-- +goose Up
-- Who made a finding decision (#180). Every decision so far came from the UI,
-- so existing rows are the user's. An agent's decision stays reviewable, and it
-- can never replace or clear one the user made.
ALTER TABLE finding_states ADD COLUMN decided_by TEXT NOT NULL DEFAULT 'user' CHECK (decided_by IN ('user', 'agent'));

-- +goose Down
ALTER TABLE finding_states DROP COLUMN decided_by;
