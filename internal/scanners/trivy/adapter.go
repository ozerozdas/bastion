package trivy

import (
	"context"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
)

// Scanner adapts ScanFS to the scanners.Scanner interface.
type Scanner struct{}

// New returns a Trivy scanner adapter.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner id.
func (*Scanner) Name() string { return "trivy" }

// Version returns the Trivy release bastion is built against.
func (*Scanner) Version() string { return Version }

// Supports reports whether Trivy can scan target kind k. Trivy scans a
// filesystem workspace, which both local paths and checked-out repos provide.
func (*Scanner) Supports(k sources.TargetKind) bool {
	return k == sources.KindPath || k == sources.KindRepo
}

// Serialized reports that Trivy's library state is process-global, so the job
// pool must run one Trivy scan at a time (ADR-001). ScanFS also holds its own
// lock as a last line of defence; this flag lets the pool avoid occupying a
// worker while a scan waits for that lock.
func (*Scanner) Serialized() bool { return true }

// Scan runs the filesystem scan against ws. Trivy's cache (vulnerability DB,
// misconfiguration checks) lives under opts.CacheDir.
func (s *Scanner) Scan(ctx context.Context, ws *sources.Workspace, opts scanners.Options) (*scanners.RawResult, error) {
	if ws == nil {
		return nil, errors.New("trivy: workspace is required")
	}
	raw, err := ScanFS(ctx, ws.Dir, opts.CacheDir, opts.SkipDirs)
	if err != nil {
		return nil, fmt.Errorf("trivy: scan: %w", err)
	}
	return &scanners.RawResult{
		Scanner:      s.Name(),
		Version:      s.Version(),
		WorkspaceDir: ws.Dir,
		Raw:          raw,
	}, nil
}
