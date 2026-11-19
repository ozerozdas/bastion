-- +goose Up
-- SLA thresholds (#190): how many days a finding of each severity may stay
-- open before it is overdue. One row per severity, seeded with a default
-- policy the settings screen can replace.
CREATE TABLE sla_thresholds (
    severity TEXT    NOT NULL PRIMARY KEY CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    days     INTEGER NOT NULL CHECK (days BETWEEN 1 AND 3650)
);

INSERT INTO sla_thresholds (severity, days) VALUES
    ('critical', 7),
    ('high', 30),
    ('medium', 90),
    ('low', 180);

-- +goose Down
DROP TABLE sla_thresholds;
