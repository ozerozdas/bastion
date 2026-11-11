// Package sources fetches scan targets into local workspaces.
//
// A Source turns a Target (a git ref, an image reference or a local path) into
// a Workspace that scanners can read. Fetching may download or unpack data, so
// every Workspace owns a Cleanup hook for whatever it created.
package sources

import (
	"context"
)

// TargetKind is the kind of artifact a target points at.
type TargetKind string

const (
	// KindRepo is a source repository checked out into a directory.
	KindRepo TargetKind = "repo"
	// KindImage is a container image. Image sources arrive in Phase 2.
	KindImage TargetKind = "image"
	// KindPath is a directory on the local machine.
	KindPath TargetKind = "path"
)

// Target identifies one artifact to scan.
type Target struct {
	Kind TargetKind
	// AssetID is the store id of the asset this target belongs to. It is part
	// of every finding fingerprint, so it must be stable across scans.
	AssetID int64
	// Ref is the source-specific reference: "owner/repo@sha", an image
	// reference or an absolute path.
	Ref string
}

// Workspace is a fetched target. Scanners read from Dir.
//
// Image is intentionally absent until image sources land in Phase 2; adding
// it now would pull go-containerregistry into the build before it is needed.
type Workspace struct {
	// Dir is the local directory scanners read. It is absolute.
	Dir string
	// Cleanup removes anything Fetch created. It is nil for sources that did
	// not create the directory (such as a local path).
	Cleanup func() error
}

// Close runs Cleanup, if any.
func (w *Workspace) Close() error {
	if w == nil || w.Cleanup == nil {
		return nil
	}
	return w.Cleanup()
}

// Source fetches one kind of target.
type Source interface {
	// Kind reports the target kind this source handles.
	Kind() TargetKind
	// Fetch materializes t into a workspace.
	Fetch(ctx context.Context, t Target) (*Workspace, error)
}
