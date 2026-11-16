//go:build unix

package opengrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeScript writes an executable stand-in for the opengrep binary.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // the stand-in must be executable.
		t.Fatalf("write script: %v", err)
	}
	return path
}

// runService wires a service that runs script instead of a downloaded module.
func runService(t *testing.T, script string, timeout time.Duration, outputCap int64) *Service {
	t.Helper()
	service := New(Config{
		ModulesDir:     t.TempDir(),
		Executable:     script,
		Timeout:        timeout,
		MaxOutputBytes: outputCap,
	})
	if err := os.MkdirAll(service.Dir(), 0o750); err != nil {
		t.Fatalf("create module dir: %v", err)
	}
	return service
}

func TestRunTimeoutBecomesWarning(t *testing.T) {
	service := runService(t, writeScript(t, "sleep 5\n"), 150*time.Millisecond, 0)
	start := time.Now()
	out, err := service.run(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("run took %s, want it killed near the timeout", elapsed)
	}
	if !out.timedOut {
		t.Fatal("run did not report a timeout")
	}
	if len(out.warnings) != 1 || !strings.Contains(out.warnings[0], "timed out") {
		t.Fatalf("warnings = %v, want one timeout warning", out.warnings)
	}
}

func TestRunOutputCapBecomesWarning(t *testing.T) {
	service := runService(t, writeScript(t, "head -c 100000 /dev/zero\n"), 30*time.Second, 1024)
	out, err := service.run(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !out.truncated {
		t.Fatal("run did not report truncated output")
	}
	if len(out.warnings) != 1 || !strings.Contains(out.warnings[0], "output exceeded") {
		t.Fatalf("warnings = %v, want one output-cap warning", out.warnings)
	}
	if int64(len(out.stdout)) > 1024 {
		t.Fatalf("stdout = %d bytes, want at most 1024", len(out.stdout))
	}
}

func TestRunCanceledScanReturnsError(t *testing.T) {
	service := runService(t, writeScript(t, "sleep 5\n"), 30*time.Second, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	_, err := service.run(ctx, t.TempDir())
	if err == nil {
		t.Fatal("run returned no error for a canceled scan")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("error = %v, want the context error", err)
	}
}
