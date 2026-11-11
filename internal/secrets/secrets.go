// Package secrets stores bastion's credentials in the OS keyring.
//
// Nothing is ever written to a plaintext file (PROJECT_SPEC.md §3, §10). When
// the keyring is unavailable (headless Linux, no Secret Service, locked
// keychain) reads fall back to BASTION_* environment variables; writes do not,
// because a user who wants env-based configuration sets those variables
// themselves.
package secrets

import "errors"

// Store is the minimal secret storage bastion needs. Keys are bastion-owned
// names such as "github-token" or "hmac-local-key"; implementations map them to
// whatever their backend expects.
type Store interface {
	// Get returns the secret for key, or an error wrapping ErrNotFound.
	Get(key string) (string, error)
	// Set stores value under key, replacing any existing value.
	Set(key, value string) error
	// Delete removes key, returning an error wrapping ErrNotFound if absent.
	Delete(key string) error
}

var (
	// ErrNotFound is returned when a key has no stored value.
	ErrNotFound = errors.New("secret not found")
	// ErrReadOnly is returned by stores that cannot be written to, such as the
	// environment fallback.
	ErrReadOnly = errors.New("secret store is read-only")
)
