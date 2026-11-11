-- +goose Up
-- Initial schema (PROJECT_SPEC.md §5). All timestamps are UTC and stored as
-- RFC3339 text. Enum-like columns are constrained with CHECK so a bad value
-- fails at the database boundary instead of surfacing later in the UI.

CREATE TABLE connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL CHECK (kind IN ('github', 'aws', 'docker')),
    name            TEXT    NOT NULL,
    -- Non-secret configuration only: org, region, profile, registry ids.
    config_json     TEXT    NOT NULL DEFAULT '{}',
    -- Keyring key holding the credential, or NULL when none is stored
    -- (PROJECT_SPEC.md §3: tokens never live in SQLite).
    secret_ref      TEXT,
    status          TEXT    NOT NULL DEFAULT 'unknown' CHECK (status IN ('ok', 'error', 'unknown')),
    last_checked_at TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (kind, name)
);

-- assets are anything bastion scans.
CREATE TABLE assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT    NOT NULL CHECK (kind IN ('repo', 'image', 'path')),
    connection_id  INTEGER REFERENCES connections (id) ON DELETE SET NULL,
    display_name   TEXT    NOT NULL,
    -- Canonical reference: "owner/repo" for repos, "registry/repo" for images.
    ref            TEXT    NOT NULL,
    default_branch TEXT,
    metadata_json  TEXT    NOT NULL DEFAULT '{}',
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    archived_at    TEXT,
    UNIQUE (kind, ref)
);

CREATE INDEX idx_assets_connection ON assets (connection_id);

-- asset_links records repo <-> image lineage (Phase 2).
CREATE TABLE asset_links (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_asset_id  INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    image_asset_id INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    source         TEXT    NOT NULL CHECK (source IN ('manual', 'label', 'heuristic')),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (repo_asset_id <> image_asset_id),
    UNIQUE (repo_asset_id, image_asset_id)
);

-- scans: one user-triggered scan of one asset.
CREATE TABLE scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    -- Resolved git SHA or image digest at scan time.
    target_ref  TEXT,
    status      TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    -- "trigger" is a SQLite keyword, hence the quoting.
    "trigger"   TEXT    NOT NULL DEFAULT 'ui' CHECK ("trigger" IN ('ui', 'cli', 'api')),
    started_at  TEXT,
    finished_at TEXT,
    error       TEXT
);

CREATE INDEX idx_scans_asset ON scans (asset_id);

-- scanner_runs: one scanner within a scan.
CREATE TABLE scanner_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scanner         TEXT    NOT NULL,
    scanner_version TEXT,
    db_version      TEXT,
    status          TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    duration_ms     INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
    error           TEXT,
    -- Optional raw scanner output kept for debugging.
    raw_path        TEXT,
    UNIQUE (scan_id, scanner)
);

-- packages: SBOM entries per scan.
CREATE TABLE packages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ecosystem TEXT    NOT NULL,
    name      TEXT    NOT NULL,
    version   TEXT,
    purl      TEXT,
    path      TEXT,
    -- NULL means "unknown".
    direct    INTEGER CHECK (direct IS NULL OR direct IN (0, 1))
);

CREATE INDEX idx_packages_scan ON packages (scan_id);

-- findings: normalized, one row per finding per scan.
CREATE TABLE findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    asset_id           INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    type               TEXT    NOT NULL CHECK (type IN ('vulnerability', 'secret', 'outdated', 'misconfig', 'license', 'malware', 'sast')),
    fingerprint        TEXT    NOT NULL,
    -- How many raw occurrences inside this scan share the fingerprint; they
    -- are stored as one finding (PROJECT_SPEC.md §5).
    occurrences        INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    severity           TEXT    NOT NULL DEFAULT 'unknown' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    title              TEXT    NOT NULL,
    -- CVE, GHSA or scanner rule id.
    rule_id            TEXT,
    package_name       TEXT,
    package_version    TEXT,
    fixed_version      TEXT,
    ecosystem          TEXT,
    -- Display location: "file:line" for secrets (the line is display only),
    -- "file + resource/cause" for misconfigurations, the package path inside
    -- the image for image findings. The secret HMAC is not stored here: it
    -- lives only in the fingerprint material, so no raw-secret column exists.
    location           TEXT,
    cvss               REAL,
    epss               REAL,
    description        TEXT,
    references_json    TEXT    NOT NULL DEFAULT '[]',
    scanner            TEXT    NOT NULL,
    first_seen_scan_id INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    status             TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ignored')),
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX idx_findings_asset_fingerprint ON findings (asset_id, fingerprint);
CREATE INDEX idx_findings_scan ON findings (scan_id);

-- finding_states: user decisions that survive across scans, keyed by
-- fingerprint so an unrelated version bump does not resurrect a finding.
CREATE TABLE finding_states (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    fingerprint TEXT    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('ignored', 'accepted_risk', 'false_positive')),
    reason      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (asset_id, fingerprint)
);

-- +goose Down
DROP TABLE finding_states;
DROP TABLE findings;
DROP TABLE packages;
DROP TABLE scanner_runs;
DROP TABLE scans;
DROP TABLE asset_links;
DROP TABLE assets;
DROP TABLE connections;
