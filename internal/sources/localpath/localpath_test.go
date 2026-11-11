package localpath

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ozerozdas/bastion/internal/sources"
)

func TestFetchDirectory(t *testing.T) {
	dir := t.TempDir()
	ws, err := New().Fetch(context.Background(), sources.Target{Kind: sources.KindPath, Ref: dir})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !filepath.IsAbs(ws.Dir) {
		t.Fatalf("Dir = %q, want an absolute path", ws.Dir)
	}
	if ws.Cleanup != nil {
		t.Fatal("local path workspace has a cleanup hook; it created nothing")
	}
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFetchRejectsInvalidTargets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name    string
		ctx     context.Context
		target  sources.Target
		wantErr bool
	}{
		{name: "empty ref", ctx: context.Background(), target: sources.Target{Kind: sources.KindPath}},
		{name: "wrong kind", ctx: context.Background(), target: sources.Target{Kind: sources.KindRepo, Ref: file}},
		{name: "file", ctx: context.Background(), target: sources.Target{Kind: sources.KindPath, Ref: file}},
		{name: "missing", ctx: context.Background(), target: sources.Target{Kind: sources.KindPath, Ref: filepath.Join(file, "nope")}},
		{name: "canceled", ctx: canceled, target: sources.Target{Kind: sources.KindPath, Ref: file}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New().Fetch(tt.ctx, tt.target); err == nil {
				t.Fatal("Fetch accepted an invalid target")
			}
		})
	}
}
