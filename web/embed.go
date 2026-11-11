// Package web embeds the built single-page application into the bastion
// binary (PROJECT_SPEC.md §3), so `bastion serve` needs no files on disk.
package web

import (
	"embed"
	"io/fs"
)

// content is web/dist as built by Vite. The directory is gitignored; the
// repository carries only dist/.gitkeep (copied from public/ on every build),
// so a bare `go build` in a fresh clone compiles and the UI layer falls back to
// its placeholder page until `npm run build` has run. `make build` and
// `make check` run that build first.
//
//go:embed all:dist
var content embed.FS

// Dist returns the built UI rooted at web/dist.
func Dist() fs.FS {
	sub, err := fs.Sub(content, "dist")
	if err != nil {
		// Unreachable: the embed pattern matched dist itself.
		return content
	}
	return sub
}
