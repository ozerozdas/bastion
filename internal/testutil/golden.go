// Package testutil holds helpers shared by bastion's tests.
package testutil

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

// AssertJSON compares got, encoded as indented JSON, with the golden file at
// path. With -update it rewrites the file instead of comparing.
func AssertJSON(t *testing.T, path string, got any) {
	t.Helper()
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("encode golden value: %v", err)
	}
	encoded = append(encoded, '\n')

	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}

	//nolint:gosec // path is a testdata path supplied by the test.
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("golden %s mismatch\n--- got ---\n%s--- want ---\n%s", path, encoded, want)
	}
}
