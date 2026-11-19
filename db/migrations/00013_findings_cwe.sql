-- +goose Up
-- Common Weakness Enumeration ids a finding maps to, as a JSON array of
-- canonical "CWE-<n>" strings (#190). Scanners that carry a mapping (Trivy,
-- OSV, opengrep) fill it; the empty array is the norm for the others and for
-- rows written before this column existed.
ALTER TABLE findings ADD COLUMN cwe TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE findings DROP COLUMN cwe;
