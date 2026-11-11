package connections

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/ozerozdas/bastion/internal/store"
)

// failingStore is a secrets.Store whose writes always fail, standing in for an
// unavailable OS keyring.
type failingStore struct{ err error }

func (s failingStore) Get(string) (string, error) { return "", s.err }
func (s failingStore) Set(string, string) error   { return s.err }
func (s failingStore) Delete(string) error        { return s.err }

// TestCreateRemovesRowWhenSecretStorageFails: a keyring failure must not leave
// a connection behind that can never be tested.
func TestCreateRemovesRowWhenSecretStorageFails(t *testing.T) {
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	service, err := NewService(db, failingStore{err: errors.New("keyring is locked")})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if _, err := service.Create(t.Context(), CreateInput{ //nolint:gosec // G101: test fixture, not a credential
		Kind:  KindGitHub,
		Name:  "orphan",
		Token: "ghp_never_stored",
	}); err == nil {
		t.Fatal("Create succeeded despite a failing secret store")
	}

	var count int
	if err := db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM connections`).Scan(&count); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d connection rows left behind, want 0", count)
	}
}
