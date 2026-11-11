-- name: ListPackagesByScan :many
-- SBOM entries of one scan, in the order findings use them. Reading a finished
-- scan back (CLI output, reports) needs the rows InsertPackage wrote.
SELECT * FROM packages
WHERE scan_id = sqlc.arg(scan_id)
ORDER BY ecosystem, name, version, path, id;

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
