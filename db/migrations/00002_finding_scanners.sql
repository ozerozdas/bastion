-- +goose Up
-- Every scanner that reported a finding, as a JSON array. scanner stays the
-- primary scanner (and the one whose fingerprint is stored), so existing rows
-- and queries keep working; scanners adds the others after cross-scanner
-- deduplication (Trivy and OSV reporting the same advisory).
ALTER TABLE findings ADD COLUMN scanners TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE findings DROP COLUMN scanners;
