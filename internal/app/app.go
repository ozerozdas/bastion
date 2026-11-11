// Package app holds bastion's process wiring: filesystem paths, bastion's own
// configuration and logging setup.
//
// Bastion's configuration is deliberately stdlib-only (PROJECT_SPEC.md §3):
// Viper appears in go.mod only because Trivy uses it internally.
package app

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// EnvDataDir overrides the data directory, which holds the SQLite database.
	EnvDataDir = "BASTION_DATA_DIR"
	// EnvCacheDir overrides the cache directory, which holds scanner databases
	// and temporary workspaces.
	EnvCacheDir = "BASTION_CACHE_DIR"

	dataDirName       = "bastion"
	cacheDirName      = "bastion"
	dbFileName        = "bastion.db"
	trivyCacheDirName = "trivy"
	workspacesDirName = "workspaces"
)

// Flags are the raw path values from the CLI. An empty string means "not set",
// which lets Resolve fall through to the environment and then the default.
type Flags struct {
	DataDir  string
	CacheDir string
}

// Paths are the resolved locations bastion reads and writes.
type Paths struct {
	DataDir  string
	CacheDir string
}

// Resolve determines the data and cache directories with precedence
// flag > environment > default (PROJECT_SPEC.md §4.4, §10).
//
// It does not create anything; callers create directories when they first need
// them so that read-only commands such as `bastion version` stay side-effect
// free.
func Resolve(flags Flags) (Paths, error) {
	dataDir := firstSet(flags.DataDir, os.Getenv(EnvDataDir))
	if dataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config dir: %w", err)
		}
		dataDir = filepath.Join(base, dataDirName)
	}

	cacheDir := firstSet(flags.CacheDir, os.Getenv(EnvCacheDir))
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user cache dir: %w", err)
		}
		cacheDir = filepath.Join(base, cacheDirName)
	}

	return Paths{
		DataDir:  filepath.Clean(dataDir),
		CacheDir: filepath.Clean(cacheDir),
	}, nil
}

// DBPath is the SQLite database file inside the data directory.
func (p Paths) DBPath() string {
	return filepath.Join(p.DataDir, dbFileName)
}

// TrivyCacheDir is the Trivy cache (vulnerability DB, checks bundle) inside the
// cache directory.
func (p Paths) TrivyCacheDir() string {
	return filepath.Join(p.CacheDir, trivyCacheDirName)
}

// WorkspacesDir is where fetched repository checkouts live, inside the cache
// directory (PROJECT_SPEC.md §4.4). It is temporary data, so it never sits in
// the data directory next to the database.
func (p Paths) WorkspacesDir() string {
	return filepath.Join(p.CacheDir, workspacesDirName)
}

// firstSet returns the first non-empty value.
func firstSet(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
