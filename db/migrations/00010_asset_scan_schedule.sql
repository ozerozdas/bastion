-- +goose Up
-- Scheduled scans (#58): per-asset cadence for one local user, run only while
-- `bastion serve` is running. Additive: the scans.trigger CHECK is left alone,
-- so no table rebuild of a parent that findings reference.
ALTER TABLE assets
ADD COLUMN scan_schedule TEXT NOT NULL DEFAULT 'off'
CHECK (scan_schedule IN ('off', 'daily', 'weekly'));

-- +goose Down
ALTER TABLE assets DROP COLUMN scan_schedule;
