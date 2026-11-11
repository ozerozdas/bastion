package secrets

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// DefaultService is the keyring service name all bastion secrets live under, so
// users can find and remove them with their OS keychain tool.
const DefaultService = "bastion"

// KeyringStore stores secrets in the OS keyring: macOS Keychain, Windows
// Credential Manager, or Linux Secret Service. go-keyring talks to the macOS
// Keychain through /usr/bin/security, so this stays CGO-free.
type KeyringStore struct {
	// Service is the keyring service name; empty means DefaultService.
	Service string
}

// NewKeyringStore returns a store backed by the OS keyring.
func NewKeyringStore() KeyringStore {
	return KeyringStore{Service: DefaultService}
}

func (s KeyringStore) service() string {
	if s.Service == "" {
		return DefaultService
	}
	return s.Service
}

// Get returns the secret stored under key.
func (s KeyringStore) Get(key string) (string, error) {
	value, err := keyring.Get(s.service(), key)
	switch {
	case err == nil:
		return value, nil
	case errors.Is(err, keyring.ErrNotFound):
		return "", fmt.Errorf("%w: %q", ErrNotFound, key)
	default:
		return "", fmt.Errorf("secrets: read %q from OS keyring: %w", key, err)
	}
}

// Set stores value under key.
func (s KeyringStore) Set(key, value string) error {
	if err := keyring.Set(s.service(), key, value); err != nil {
		return fmt.Errorf("secrets: write %q to OS keyring: %w", key, err)
	}
	return nil
}

// Delete removes key.
func (s KeyringStore) Delete(key string) error {
	err := keyring.Delete(s.service(), key)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	default:
		return fmt.Errorf("secrets: delete %q from OS keyring: %w", key, err)
	}
}
