// Package localpath provides a Source for directories on the local machine.
package localpath

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ozerozdas/bastion/internal/sources"
)

// Source resolves local-path targets. It creates nothing, so the workspaces it
// returns have no cleanup hook.
type Source struct{}

// New returns a local-path source.
func New() *Source { return &Source{} }

// Kind reports that this source handles path targets.
func (*Source) Kind() sources.TargetKind { return sources.KindPath }

// Fetch validates t.Ref and returns it as an absolute workspace directory.
func (*Source) Fetch(ctx context.Context, t sources.Target) (*sources.Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.Kind != sources.KindPath {
		return nil, fmt.Errorf("localpath: unsupported target kind %q", t.Kind)
	}
	if t.Ref == "" {
		return nil, errors.New("localpath: target ref is required")
	}
	abs, err := filepath.Abs(t.Ref)
	if err != nil {
		return nil, fmt.Errorf("localpath: resolve %q: %w", t.Ref, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("localpath: stat %q: %w", t.Ref, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("localpath: target %q is not a directory", t.Ref)
	}
	return &sources.Workspace{Dir: abs}, nil
}
