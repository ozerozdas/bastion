package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
)

// Scanner adapts ScanDir to the scanners.Scanner interface.
type Scanner struct{}

// New returns a Gitleaks scanner adapter.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner id.
func (*Scanner) Name() string { return "gitleaks" }

// Version returns the Gitleaks release bastion is built against.
func (*Scanner) Version() string { return Version }

// Supports reports whether Gitleaks can scan target kind k. Gitleaks reads a
// working tree, which both local paths and checked-out repos provide.
func (*Scanner) Supports(k sources.TargetKind) bool {
	return k == sources.KindPath || k == sources.KindRepo
}

// Scan runs the working-tree scan against ws. Secret matches are redacted
// before they leave this package; the raw secret only feeds the HMAC.
func (s *Scanner) Scan(ctx context.Context, ws *sources.Workspace, opts scanners.Options) (*scanners.RawResult, error) {
	if ws == nil {
		return nil, errors.New("gitleaks: workspace is required")
	}
	found, err := ScanDir(ctx, ws.Dir, opts.HMACKey, opts.SkipDirs)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: scan: %w", err)
	}
	raw, err := json.Marshal(found)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: encode findings: %w", err)
	}
	return &scanners.RawResult{
		Scanner:      s.Name(),
		Version:      s.Version(),
		WorkspaceDir: ws.Dir,
		Raw:          raw,
		Data:         found,
	}, nil
}
