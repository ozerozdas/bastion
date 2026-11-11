package secrets

import (
	"fmt"
	"os"
	"strings"
)

// envPrefix is prepended to every environment variable that can stand in for a
// keyring entry (PROJECT_SPEC.md §10).
const envPrefix = "BASTION_"

// EnvStore reads secrets from BASTION_* environment variables. It is read-only:
// bastion never writes configuration back into the environment.
type EnvStore struct{}

// EnvVarName maps a store key to its environment variable name, e.g.
// "github-token" becomes "BASTION_GITHUB_TOKEN".
func EnvVarName(key string) string {
	var b strings.Builder
	b.WriteString(envPrefix)
	for _, r := range strings.ToUpper(key) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Get reads the environment variable for key. Unset or empty variables are
// treated as absent.
func (EnvStore) Get(key string) (string, error) {
	name := EnvVarName(key)
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%w: %s is not set", ErrNotFound, name)
	}
	return value, nil
}

// Set always fails: the environment fallback is read-only.
func (EnvStore) Set(key, _ string) error {
	return fmt.Errorf("secrets: %s (for %q) is read-only: %w", EnvVarName(key), key, ErrReadOnly)
}

// Delete always fails: the environment fallback is read-only.
func (EnvStore) Delete(key string) error {
	return fmt.Errorf("secrets: %s (for %q) is read-only: %w", EnvVarName(key), key, ErrReadOnly)
}
