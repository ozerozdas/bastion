package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	// HMACKeyName is the keyring key that holds the base64-encoded 32-byte
	// local HMAC key.
	HMACKeyName = "hmac-local-key"
	// EnvHMACKey is the environment fallback for the local HMAC key, used when
	// the keyring is unavailable. The value must be base64-encoded 32 bytes.
	EnvHMACKey = "BASTION_HMAC_KEY"

	localKeySize = 32
)

// localKeyMu serializes get-or-create so two concurrent first callers cannot
// generate different keys (one of which would not be the stored one).
var localKeyMu sync.Mutex

// LocalKey returns the 32-byte key bastion uses to HMAC secrets before storing
// them (PROJECT_SPEC.md §4.3). A plain hash is not used because low-entropy
// secrets would be brute-forceable from the database.
//
// The key is created on first use and stored base64-encoded under HMACKeyName.
// If the keyring is unavailable, the key is read from EnvHMACKey instead; if
// that is also absent, the returned error explains how to set it.
func LocalKey(store Store) ([]byte, error) {
	if store == nil {
		return nil, errors.New("secrets: store is required")
	}

	localKeyMu.Lock()
	defer localKeyMu.Unlock()

	encoded, err := store.Get(HMACKeyName)
	if err == nil {
		return decodeLocalKey(HMACKeyName, encoded)
	}
	if !errors.Is(err, ErrNotFound) {
		// The keyring could not be read at all; environment fallback (§10).
		return localKeyFromEnv(fmt.Errorf("read %q from keyring: %w", HMACKeyName, err))
	}

	key := make([]byte, localKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate local HMAC key: %w", err)
	}
	if err := store.Set(HMACKeyName, base64.StdEncoding.EncodeToString(key)); err != nil {
		return localKeyFromEnv(fmt.Errorf("store %q: %w", HMACKeyName, err))
	}
	return key, nil
}

// decodeLocalKey decodes and validates a base64-encoded key of the expected
// size.
func decodeLocalKey(name, encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("secrets: %s is not valid base64: %w", name, err)
	}
	if len(key) != localKeySize {
		return nil, fmt.Errorf("secrets: %s must decode to %d bytes, got %d", name, localKeySize, len(key))
	}
	return key, nil
}

// localKeyFromEnv reads the fallback key from EnvHMACKey. cause describes why
// the keyring path failed and is included in the error when no fallback exists.
func localKeyFromEnv(cause error) ([]byte, error) {
	encoded := strings.TrimSpace(os.Getenv(EnvHMACKey))
	if encoded == "" {
		return nil, fmt.Errorf(
			"secrets: no local HMAC key available (%w); set %s to a base64-encoded %d-byte key, e.g. `openssl rand -base64 %d`",
			cause, EnvHMACKey, localKeySize, localKeySize,
		)
	}
	return decodeLocalKey(EnvHMACKey, encoded)
}
