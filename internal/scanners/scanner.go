// Package scanners defines the boundary between bastion and its scanners.
//
// A Scanner adapter owns every dependency on one scanner library; callers see
// only RawResult. Packages outside internal/scanners/<name>/ must never import
// that scanner's library (PROJECT_SPEC.md §4.2).
package scanners

import (
	"context"
	"encoding/json"

	"github.com/ozerozdas/bastion/internal/sources"
)

// Options are per-scan inputs shared by scanner adapters.
type Options struct {
	// CacheDir holds scanner data such as Trivy's vulnerability DB. Adapters
	// that need no cache may ignore it.
	CacheDir string
	// HMACKey keys secret fingerprints (Gitleaks). It must never be logged or
	// persisted; adapters that do not scan secrets may ignore it.
	HMACKey []byte
	// SkipDirs are directories to leave out of the scan, each relative to the
	// scanned workspace root (e.g. "testdata"). Their findings must not appear
	// in the result. Empty scans everything.
	SkipDirs []string
}

// RawResult is one scanner's output, before normalization.
type RawResult struct {
	// Scanner is the scanner name ("trivy", "gitleaks").
	Scanner string
	// Version is the scanner library version bastion is built against.
	Version string
	// WorkspaceDir is the directory that was scanned. Normalizers use it to
	// strip temporary workspace prefixes from locations.
	WorkspaceDir string
	// Raw is the scanner's native JSON output. At least one of Raw and Data is
	// set.
	Raw json.RawMessage
	// Data is an optional typed payload for scanners whose native output is
	// already free of library types. At least one of Raw and Data is set.
	Data any
}

// Scanner scans one workspace.
type Scanner interface {
	// Name is the stable scanner id stored in scanner_runs.
	Name() string
	// Version is the scanner library version.
	Version() string
	// Supports reports whether the scanner can scan target kind k.
	Supports(k sources.TargetKind) bool
	// Scan runs the scanner against ws. Scans must honour ctx cancellation.
	Scan(ctx context.Context, ws *sources.Workspace, opts Options) (*RawResult, error)
}
