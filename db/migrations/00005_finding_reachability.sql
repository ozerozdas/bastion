-- +goose Up
-- Go reachability (#37). govulncheck answers whether a vulnerable function is
-- actually called in the scanned workspace, which is scan-specific: a later
-- commit can start calling it. The state therefore lives on the scan's finding
-- row instead of a finding_states-style decision keyed by fingerprint.
--
-- NULL means "not classified": the opt-in enrichment is off, or the finding is
-- not a Go vulnerability. 'unknown' is a real answer: the enrichment ran (or
-- was asked to) and could not decide.
ALTER TABLE findings ADD COLUMN reachability TEXT
    CHECK (reachability IN ('reachable', 'unreachable', 'unknown'));

-- +goose Down
ALTER TABLE findings DROP COLUMN reachability;
