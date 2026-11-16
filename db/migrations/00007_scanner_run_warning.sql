-- +goose Up
-- Partial-coverage warnings from a scanner (#33). A scanner can succeed with
-- findings and still not cover everything (a timeout cut its output off, a
-- result was outside the workspace). That is not an error: the run status
-- stays succeeded and the note lives in its own column, so a failed run's
-- error and a successful run's warning cannot be confused.
ALTER TABLE scanner_runs ADD COLUMN warning TEXT;

-- +goose Down
ALTER TABLE scanner_runs DROP COLUMN warning;
