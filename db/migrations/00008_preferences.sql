-- +goose Up
-- Preferences (#150): per-install UI choices. They used to live only in the
-- browser's localStorage, which is scoped to one origin, so changing the port
-- lost them. A small key/value table keeps the choices with the install while
-- localStorage remains the first-paint cache.
--
-- "key" is quoted because SQLite reserves the word in PRIMARY KEY.
CREATE TABLE preferences (
    "key"      TEXT PRIMARY KEY,
    value      TEXT NOT NULL CHECK (length(value) <= 64),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- +goose Down
DROP TABLE preferences;
