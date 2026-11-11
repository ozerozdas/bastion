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
	// local HMAC key. Its environment name (EnvVarName) is EnvHMACKey.
	HMACKeyName = "hmac-key"
	// EnvHMACKey overrides the keyring when set: headless machines and CI use
	// it. The value must be base64-encoded 32 bytes.
	EnvHMACKey = "BASTION_HMAC_KEY"

	localKeySize = 32
)

// localKeyMu serializes get-or-create within this process. Across processes
// the read-back after Set makes every caller use whichever key was stored last.
var localKeyMu sync.Mutex

// LocalKey returns the 32-byte key bastion uses to HMAC secrets before storing
// them (PROJECT_SPEC.md §4.3). A plain hash is not used because low-entropy
// secrets would be brute-forceable from the database.
//
// Resolution is deterministic so fingerprints stay stable across runs:
//  1. EnvHMACKey, if set, always wins.
//  2. Otherwise the key stored under HMACKeyName; created on first use.
//  3. If the keyring cannot be read or written, an error explains how to set
//     EnvHMACKey. A random throwaway key is never returned.
func LocalKey(store Store) ([]byte, error) {
	if store == nil {
		return nil, errors.New("secrets: store is required")
	}
	if encoded := strings.TrimSpace(os.Getenv(EnvHMACKey)); encoded != "" {
		return decodeLocalKey(EnvHMACKey, encoded)
	}

	localKeyMu.Lock()
	defer localKeyMu.Unlock()

	encoded, err := store.Get(HMACKeyName)
	if err == nil {
		return decodeLocalKey(HMACKeyName, encoded)
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, noKeyError(fmt.Errorf("read %q from keyring: %w", HMACKeyName, err))
	}

	key := make([]byte, localKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate local HMAC key: %w", err)
	}
	if err := store.Set(HMACKeyName, base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, noKeyError(fmt.Errorf("store %q: %w", HMACKeyName, err))
	}
	// Read back: another bastion process may have stored its key concurrently.
	stored, err := store.Get(HMACKeyName)
	if err != nil {
		return nil, noKeyError(fmt.Errorf("read back %q: %w", HMACKeyName, err))
	}
	return decodeLocalKey(HMACKeyName, stored)
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

// noKeyError wraps a keyring failure with a hint on how to provide the key.
func noKeyError(cause error) error {
	return fmt.Errorf(
		"secrets: no local HMAC key available (%w); set %s to a base64-encoded %d-byte key, e.g. `openssl rand -base64 %d`",
		cause, EnvHMACKey, localKeySize, localKeySize,
	)
}
