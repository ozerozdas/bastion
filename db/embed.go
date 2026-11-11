// Package db holds bastion's database schema as goose-annotated SQL
// migrations, embedded into the binary so startup never needs the source tree
// (PROJECT_SPEC.md §3, §4.1).
//
// Schema changes always arrive as a new numbered migration; applied migrations
// are never edited (PROJECT_SPEC.md §9).
package db

import "embed"

// Migrations is the embedded db/migrations directory. Callers root a
// filesystem at "migrations" before handing it to goose.
//
//go:embed migrations/*.sql
var Migrations embed.FS
