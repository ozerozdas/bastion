package secrets

import "fmt"

// probeKey is a throwaway keyring entry used to test availability. It is
// deleted again, so it never holds data.
const probeKey = "bastion-availability-probe"

// Probe checks that store supports set, get and delete of a throwaway key. It
// leaves no entry behind on success.
func Probe(store Store) error {
	const probeValue = "ok"

	if err := store.Set(probeKey, probeValue); err != nil {
		return fmt.Errorf("secrets: keyring probe: set: %w", err)
	}

	value, err := store.Get(probeKey)
	if err != nil {
		_ = store.Delete(probeKey) // best-effort cleanup
		return fmt.Errorf("secrets: keyring probe: get: %w", err)
	}
	if value != probeValue {
		_ = store.Delete(probeKey)
		return fmt.Errorf("secrets: keyring probe: got %q, want %q", value, probeValue)
	}

	if err := store.Delete(probeKey); err != nil {
		return fmt.Errorf("secrets: keyring probe: delete: %w", err)
	}
	return nil
}

// Available reports whether the OS keyring is usable. `bastion doctor` uses it
// to decide whether to warn about the BASTION_* environment fallback.
func Available() error {
	return Probe(NewKeyringStore())
}
