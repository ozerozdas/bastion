package secrets

// NewStore returns the production secret store: the OS keyring with a
// read-through to BASTION_* environment variables.
//
// Reads try the keyring first and fall back to the environment when a key is
// absent or the keyring cannot serve it. Writes and deletes always go to the
// keyring: a plaintext fallback file is forbidden (PROJECT_SPEC.md §10).
func NewStore() Store {
	return newFallbackStore(NewKeyringStore(), EnvStore{})
}

// fallbackStore reads from primary and, when that fails, from secondary.
type fallbackStore struct {
	primary   Store
	secondary Store
}

func newFallbackStore(primary, secondary Store) fallbackStore {
	return fallbackStore{primary: primary, secondary: secondary}
}

// Get returns the value from the primary store, or the secondary store's value
// when the primary has none. If both fail, the primary's error is returned so
// callers see the real keyring failure rather than a misleading ErrNotFound.
func (s fallbackStore) Get(key string) (string, error) {
	value, err := s.primary.Get(key)
	if err == nil {
		return value, nil
	}
	if fallback, fallbackErr := s.secondary.Get(key); fallbackErr == nil {
		return fallback, nil
	}
	return "", err
}

// Set writes to the primary store only.
func (s fallbackStore) Set(key, value string) error {
	return s.primary.Set(key, value)
}

// Delete removes from the primary store only.
func (s fallbackStore) Delete(key string) error {
	return s.primary.Delete(key)
}
