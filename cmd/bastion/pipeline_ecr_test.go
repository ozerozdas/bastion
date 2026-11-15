package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
)

// TestResolveImageTargetRefusesOrphanedECR: an ECR image whose connection was
// deleted must fail clearly instead of falling back to the local Docker daemon.
func TestResolveImageTargetRefusesOrphanedECR(t *testing.T) {
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tokens, err := connections.NewService(db, secrets.NewMemoryStore())
	if err != nil {
		t.Fatalf("connections.NewService: %v", err)
	}

	registry := "143709573002.dkr.ecr.eu-central-1.amazonaws.com"
	ref := registry + "/t2n-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result, err := db.ExecContext(t.Context(), `
		INSERT INTO assets (kind, connection_id, display_name, ref, metadata_json)
		VALUES ('image', NULL, 't2n-api:latest', ?, ?)`,
		ref, `{"registry":"`+registry+`","repository":"t2n-api","tag":"latest"}`)
	if err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("asset id: %v", err)
	}

	_, _, err = resolveImageTarget(t.Context(), db, tokens, sources.Target{
		Kind: sources.KindImage, AssetID: id, Ref: ref,
	})
	if err == nil || !strings.Contains(err.Error(), "connection for this image was removed") {
		t.Fatalf("resolveImageTarget error = %v, want the removed-connection error", err)
	}
}
