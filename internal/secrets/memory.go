package secrets

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory Store for tests. It never touches the OS
// keychain, so unit tests do not prompt the user or depend on a keyring.
type MemoryStore struct {
	mu     sync.Mutex
	values map[string]string
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{values: make(map[string]string)}
}

// Get returns the value stored under key.
func (s *MemoryStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.values[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	return value, nil
}

// Set stores value under key.
func (s *MemoryStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.values == nil {
		s.values = make(map[string]string)
	}
	s.values[key] = value
	return nil
}

// Delete removes key.
func (s *MemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.values[key]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	delete(s.values, key)
	return nil
}
