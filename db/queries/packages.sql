-- name: InsertPackage :exec
INSERT INTO packages (scan_id, ecosystem, name, version, purl, path, direct)
VALUES (
    sqlc.arg(scan_id),
    sqlc.arg(ecosystem),
    sqlc.arg(name),
    sqlc.narg(version),
    sqlc.narg(purl),
    sqlc.narg(path),
    sqlc.narg(direct)
);
