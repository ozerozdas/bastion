-- +goose Up
-- An accepted risk should not mean forever (#32). expires_at is optional: NULL
-- keeps the decision until it is cleared. The read queries compare it with a
-- passed-in `now` instead of the database clock, so a decision expires in the
-- same instant for every reader and a test can pin the clock.
--
-- Stored in the canonical UTC form of store.FormatTimestamp
-- (YYYY-MM-DDTHH:MM:SS.sssZ), so a plain text comparison orders correctly.
ALTER TABLE finding_states ADD COLUMN expires_at TEXT;

-- +goose Down
ALTER TABLE finding_states DROP COLUMN expires_at;
