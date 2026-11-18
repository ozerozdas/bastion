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
	// DockerHost is the local Docker daemon host image scans read from, in the
	// form "unix:///var/run/docker.sock". Empty lets the scanner resolve it.
	DockerHost string
	// Progress receives the pipeline stage an adapter is waiting on before it
	// can start scanning, e.g. PhaseWaitingDB while the vulnerability DB is
	// downloaded. It is called from the scanning goroutine and must not block.
	// Nil means no reporting.
	Progress func(stage string)
}

// PhaseWaitingDB is the stage a scanner reports through Options.Progress while
// it waits for data it needs before scanning, such as Trivy's vulnerability DB.
const PhaseWaitingDB = "wait_db"

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
	// Warnings report partial coverage: the scanner produced findings but
	// could not cover everything (output was cut off, a result was outside the
	// workspace, and so on). They never fail a scan; callers surface them
	// beside the scanner run.
	Warnings []string
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

// ImageSource is the repository an image declares it was built from, through
// the OCI labels org.opencontainers.image.source and .revision. It is a neutral
// shape: the scanner adapter that can read it owns the format, the pipeline
// only passes it on.
//
// OSFamily and OSName are the operating system the scanner detected in the
// target, for example "alpine" and "3.18.4"; both are empty when it found none.
type ImageSource struct {
	URL      string
	Revision string
	OSFamily string
	OSName   string
}

// ImageSourceReader is implemented by adapters whose raw output can carry an
// image's OCI source labels (Trivy reads them from the image config). Callers
// that link images to repositories type-assert for it, so scanners without the
// concept need no method.
type ImageSourceReader interface {
	ImageSource(raw *RawResult) ImageSource
}
