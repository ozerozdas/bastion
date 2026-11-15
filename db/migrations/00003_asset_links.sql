-- +goose Up
-- asset_links records the repository an image was built from (#19, #20).
--
-- 00001 created the table for a later phase and nothing ever wrote to it, so
-- it is rebuilt rather than altered: SQLite cannot change a CHECK constraint or
-- add a UNIQUE constraint in place. The shape here is 1:N — one image links to
-- at most one repository (UNIQUE image_asset_id), a repository can have many
-- images — and it names the two sources bastion writes: a user's manual choice
-- and the image's own OCI labels. A manual link is never replaced by a label.
DROP TABLE asset_links;

CREATE TABLE asset_links (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_asset_id  INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    image_asset_id INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    source         TEXT    NOT NULL CHECK (source IN ('manual', 'oci')),
    -- org.opencontainers.image.revision of the image, when its labels had one.
    revision       TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (repo_asset_id <> image_asset_id),
    UNIQUE (image_asset_id)
);

CREATE INDEX idx_asset_links_repo ON asset_links (repo_asset_id);

-- +goose Down
DROP TABLE asset_links;

CREATE TABLE asset_links (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_asset_id  INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    image_asset_id INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    source         TEXT    NOT NULL CHECK (source IN ('manual', 'label', 'heuristic')),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (repo_asset_id <> image_asset_id),
    UNIQUE (repo_asset_id, image_asset_id)
);
