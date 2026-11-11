package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Set the XDG variables too so the test also means the same thing on Linux.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	configBase, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("UserCacheDir: %v", err)
	}
	defaultData := filepath.Join(configBase, "bastion")
	defaultCache := filepath.Join(cacheBase, "bastion")

	tests := []struct {
		name      string
		flags     Flags
		dataEnv   string
		cacheEnv  string
		wantData  string
		wantCache string
	}{
		{
			name:      "defaults",
			wantData:  defaultData,
			wantCache: defaultCache,
		},
		{
			name:      "env overrides default",
			dataEnv:   "/env/data",
			cacheEnv:  "/env/cache",
			wantData:  "/env/data",
			wantCache: "/env/cache",
		},
		{
			name:      "flag overrides env",
			flags:     Flags{DataDir: "/flag/data", CacheDir: "/flag/cache"},
			dataEnv:   "/env/data",
			cacheEnv:  "/env/cache",
			wantData:  "/flag/data",
			wantCache: "/flag/cache",
		},
		{
			name:      "flag without env",
			flags:     Flags{DataDir: "/flag/data", CacheDir: "/flag/cache"},
			wantData:  "/flag/data",
			wantCache: "/flag/cache",
		},
		{
			name:      "paths are cleaned",
			flags:     Flags{DataDir: "/flag/./data/", CacheDir: "/flag//cache/"},
			wantData:  "/flag/data",
			wantCache: "/flag/cache",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvDataDir, tc.dataEnv)
			t.Setenv(EnvCacheDir, tc.cacheEnv)

			got, err := Resolve(tc.flags)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.DataDir != tc.wantData {
				t.Errorf("DataDir = %q, want %q", got.DataDir, tc.wantData)
			}
			if got.CacheDir != tc.wantCache {
				t.Errorf("CacheDir = %q, want %q", got.CacheDir, tc.wantCache)
			}
		})
	}
}

func TestPaths(t *testing.T) {
	paths := Paths{DataDir: "/data", CacheDir: "/cache"}

	if got, want := paths.DBPath(), filepath.Join("/data", "bastion.db"); got != want {
		t.Errorf("DBPath() = %q, want %q", got, want)
	}
	if got, want := paths.TrivyCacheDir(), filepath.Join("/cache", "trivy"); got != want {
		t.Errorf("TrivyCacheDir() = %q, want %q", got, want)
	}
}
