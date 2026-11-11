package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()

	if _, err := store.Get("github-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store = %v, want ErrNotFound", err)
	}
	if err := store.Set("github-token", "ghp_test"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("github-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_test" {
		t.Fatalf("Get = %q, want ghp_test", got)
	}
	if err := store.Delete("github-token"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("github-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete("github-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing = %v, want ErrNotFound", err)
	}
}

func TestEnvVarName(t *testing.T) {
	// The values are environment variable names, not credentials.
	tests := map[string]string{ //nolint:gosec // G101 false positive: names, not secrets
		"github-token":   "BASTION_GITHUB_TOKEN",
		"hmac-local-key": "BASTION_HMAC_LOCAL_KEY",
		"aws/sso_cache":  "BASTION_AWS_SSO_CACHE",
	}
	for key, want := range tests {
		if got := EnvVarName(key); got != want {
			t.Errorf("EnvVarName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestEnvStore(t *testing.T) {
	t.Setenv(EnvVarName("github-token"), "ghp_from_env")
	store := EnvStore{}

	got, err := store.Get("github-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_from_env" {
		t.Fatalf("Get = %q, want ghp_from_env", got)
	}
	if _, err := store.Get("aws-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get unset = %v, want ErrNotFound", err)
	}
	if err := store.Set("github-token", "x"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Set = %v, want ErrReadOnly", err)
	}
	if err := store.Delete("github-token"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Delete = %v, want ErrReadOnly", err)
	}
}

func TestFallbackStore(t *testing.T) {
	t.Setenv(EnvVarName("github-token"), "ghp_from_env")
	primary := NewMemoryStore()
	store := newFallbackStore(primary, EnvStore{})

	// Primary misses, environment wins.
	got, err := store.Get("github-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_from_env" {
		t.Fatalf("Get = %q, want ghp_from_env", got)
	}

	// Primary beats the environment.
	if err := store.Set("github-token", "ghp_from_keyring"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err = store.Get("github-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_from_keyring" {
		t.Fatalf("Get = %q, want ghp_from_keyring", got)
	}

	// Writes never reach the read-only fallback.
	if err := primary.Delete("github-token"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, err = store.Get("github-token"); err != nil || got != "ghp_from_env" {
		t.Fatalf("Get after Delete = (%q, %v), want (ghp_from_env, nil)", got, err)
	}

	// Both misses: the primary error is reported.
	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestFallbackStoreReportsPrimaryFailure(t *testing.T) {
	primaryErr := errors.New("keyring unavailable")
	store := newFallbackStore(failingStore{err: primaryErr}, EnvStore{})

	if _, err := store.Get("github-token"); !errors.Is(err, primaryErr) {
		t.Fatalf("Get = %v, want the primary error", err)
	}
}

func TestProbe(t *testing.T) {
	store := NewMemoryStore()
	if err := Probe(store); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if _, err := store.Get(probeKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("probe key left behind: %v", err)
	}

	if err := Probe(failingStore{err: errors.New("no keyring")}); err == nil {
		t.Fatal("Probe succeeded against a failing store")
	}
}

func TestLocalKeyCreatesAndPersists(t *testing.T) {
	store := NewMemoryStore()

	key, err := LocalKey(store)
	if err != nil {
		t.Fatalf("LocalKey: %v", err)
	}
	if len(key) != localKeySize {
		t.Fatalf("key length = %d, want %d", len(key), localKeySize)
	}

	encoded, err := store.Get(HMACKeyName)
	if err != nil {
		t.Fatalf("get stored key: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("stored key is not base64: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("stored key differs from returned key")
	}

	again, err := LocalKey(store)
	if err != nil {
		t.Fatalf("second LocalKey: %v", err)
	}
	if !bytes.Equal(again, key) {
		t.Fatal("second LocalKey returned a different key")
	}
}

func TestLocalKeyEnvFallback(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, localKeySize)
	t.Setenv(EnvHMACKey, base64.StdEncoding.EncodeToString(want))

	got, err := LocalKey(failingStore{err: errors.New("keyring unavailable")})
	if err != nil {
		t.Fatalf("LocalKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("key = %x, want %x", got, want)
	}
}

func TestLocalKeyUnavailableWithoutFallback(t *testing.T) {
	t.Setenv(EnvHMACKey, "")

	_, err := LocalKey(failingStore{err: errors.New("keyring unavailable")})
	if err == nil {
		t.Fatal("LocalKey returned nil error")
	}
	if !strings.Contains(err.Error(), EnvHMACKey) {
		t.Fatalf("error %q does not mention %s", err, EnvHMACKey)
	}
}

func TestLocalKeyRejectsCorruptStoredKey(t *testing.T) {
	tests := map[string]string{
		"not base64":  "%%%",
		"wrong size":  base64.StdEncoding.EncodeToString([]byte("too short")),
		"empty value": "",
	}

	for name, stored := range tests {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStore()
			if err := store.Set(HMACKeyName, stored); err != nil {
				t.Fatalf("Set: %v", err)
			}
			if _, err := LocalKey(store); err == nil {
				t.Fatal("LocalKey accepted a corrupt stored key")
			}
		})
	}
}

func TestLocalKeyRejectsInvalidEnvFallback(t *testing.T) {
	t.Setenv(EnvHMACKey, "not-base64")

	if _, err := LocalKey(failingStore{err: errors.New("keyring unavailable")}); err == nil {
		t.Fatal("LocalKey accepted an invalid env key")
	}
}

// failingStore is a Store whose every operation fails with err. It stands in
// for an unavailable OS keyring.
type failingStore struct {
	err error
}

func (s failingStore) Get(string) (string, error) { return "", s.err }
func (s failingStore) Set(string, string) error   { return s.err }
func (s failingStore) Delete(string) error        { return s.err }

func TestHMACKeyEnvNameMatches(t *testing.T) {
	if got := EnvVarName(HMACKeyName); got != EnvHMACKey {
		t.Fatalf("EnvVarName(%q) = %q, want %q", HMACKeyName, got, EnvHMACKey)
	}
}

func TestLocalKeyEnvWinsOverKeyring(t *testing.T) {
	store := NewMemoryStore()
	if _, err := LocalKey(store); err != nil {
		t.Fatalf("LocalKey: %v", err)
	}
	want := bytes.Repeat([]byte{7}, localKeySize)
	t.Setenv(EnvHMACKey, base64.StdEncoding.EncodeToString(want))
	got, err := LocalKey(store)
	if err != nil {
		t.Fatalf("LocalKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("env key did not override the stored key")
	}
}
