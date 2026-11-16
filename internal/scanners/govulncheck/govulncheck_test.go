package govulncheck

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
)

// recordedOutput is govulncheck's own JSON for the fixture module, recorded
// once so the mapping is tested without a toolchain or the network. It holds
// GO-2026-6860 (html.Parse is called, symbol-level) and GO-2026-5026 (idna is
// imported, package-level only).
func recordedOutput(t *testing.T) io.Reader {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "recorded.json"))
	if err != nil {
		t.Fatalf("open recorded output: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// recordedStates is the analysis the recorded stream describes.
func recordedStates(t *testing.T) map[string]map[string]bool {
	t.Helper()
	states, err := parse(recordedOutput(t))
	if err != nil {
		t.Fatalf("parse recorded output: %v", err)
	}
	return states
}

// goFinding is a Go dependency vulnerability as a scanner would report it.
func goFinding(ruleID, pkg string) findings.Finding {
	return findings.Finding{
		Type:        findings.TypeVulnerability,
		Ecosystem:   "go",
		RuleID:      ruleID,
		PackageName: pkg,
		Title:       "vulnerability " + ruleID,
	}
}

// moduleDir creates a directory holding a go.mod.
func moduleDir(t *testing.T, root string, parts ...string) string {
	t.Helper()
	dir := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create module dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

// TestParseAndClassify is the Done-when test for #37: the fixture's called
// vulnerable function is reachable and its uncalled one is unreachable.
func TestParseAndClassify(t *testing.T) {
	states := recordedStates(t)

	tests := []struct {
		name string
		f    findings.Finding
		want findings.Reachability
	}{
		{
			name: "called function is reachable",
			f:    goFinding("GO-2026-6860", "golang.org/x/net"),
			want: findings.ReachabilityReachable,
		},
		{
			name: "alias of the called function is reachable",
			f:    goFinding("CVE-2026-78661", "golang.org/x/net"),
			want: findings.ReachabilityReachable,
		},
		{
			name: "uncalled package is unreachable",
			f:    goFinding("GO-2026-5026", "golang.org/x/net"),
			want: findings.ReachabilityUnreachable,
		},
		{
			name: "alias of the uncalled package is unreachable",
			f:    goFinding("CVE-2026-39821", "golang.org/x/net"),
			want: findings.ReachabilityUnreachable,
		},
		{
			name: "advisory govulncheck did not report is unknown",
			f:    goFinding("GO-2000-0001", "golang.org/x/net"),
			want: findings.ReachabilityUnknown,
		},
		{
			name: "ids are compared case-insensitively",
			f:    goFinding("go-2026-6860 ", "golang.org/x/net"),
			want: findings.ReachabilityReachable,
		},
		{
			name: "package below the module is attributed by prefix",
			f:    goFinding("GO-2026-6860", "golang.org/x/net/html"),
			want: findings.ReachabilityReachable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.f, states); got != tt.want {
				t.Errorf("classify(%s, %s) = %q, want %q", tt.f.RuleID, tt.f.PackageName, got, tt.want)
			}
		})
	}
}

// TestEnrichMarksFindings proves Enrich sets the answers on the findings and
// leaves non-Go findings alone. The runner seam returns the recorded output, so
// no process is started.
func TestEnrichMarksFindings(t *testing.T) {
	dir := moduleDir(t, t.TempDir())

	s := New(Config{
		DataDir:  t.TempDir(),
		LookPath: func(string) (string, error) { return "/usr/bin/go", nil },
		Run: func(context.Context, string) (map[string]map[string]bool, error) {
			return recordedStates(t), nil
		},
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	fs := []findings.Finding{
		goFinding("GO-2026-6860", "golang.org/x/net"),
		goFinding("GO-2026-5026", "golang.org/x/net"),
		{Type: findings.TypeVulnerability, Ecosystem: "npm", RuleID: "CVE-2021-44228"},
	}
	ran, err := s.Enrich(context.Background(), dir, fs)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !ran {
		t.Fatal("enrich did not run on a Go module")
	}
	if fs[0].Reachability != findings.ReachabilityReachable {
		t.Errorf("called finding = %q, want reachable", fs[0].Reachability)
	}
	if fs[1].Reachability != findings.ReachabilityUnreachable {
		t.Errorf("uncalled finding = %q, want unreachable", fs[1].Reachability)
	}
	if fs[2].Reachability != "" {
		t.Errorf("npm finding = %q, want untouched", fs[2].Reachability)
	}
}

// TestEnrichMultiModule proves states are keyed by module path: the same
// advisory reachable in one module does not mark another module's finding
// reachable.
func TestEnrichMultiModule(t *testing.T) {
	root := t.TempDir()
	moduleDir(t, root, "one")
	moduleDir(t, root, "two")

	s := New(Config{
		DataDir:  t.TempDir(),
		LookPath: func(string) (string, error) { return "/usr/bin/go", nil },
		Run: func(_ context.Context, dir string) (map[string]map[string]bool, error) {
			switch filepath.Base(dir) {
			case "one":
				return map[string]map[string]bool{"GO-2026-0001": {"example.com/one": true}}, nil
			default:
				return map[string]map[string]bool{"GO-2026-0002": {"example.com/two": false}}, nil
			}
		},
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	fs := []findings.Finding{
		goFinding("GO-2026-0001", "example.com/one/sub"),
		goFinding("GO-2026-0002", "example.com/two"),
		goFinding("GO-2026-0001", "example.com/three"),
	}
	if _, err := s.Enrich(context.Background(), root, fs); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if fs[0].Reachability != findings.ReachabilityReachable {
		t.Errorf("module one = %q, want reachable", fs[0].Reachability)
	}
	if fs[1].Reachability != findings.ReachabilityUnreachable {
		t.Errorf("module two = %q, want unreachable", fs[1].Reachability)
	}
	if fs[2].Reachability != findings.ReachabilityUnknown {
		t.Errorf("unreported module = %q, want unknown", fs[2].Reachability)
	}
}

// TestEnrichWithoutGoKeepsUnknown proves a missing toolchain degrades to
// unknown instead of failing.
func TestEnrichWithoutGoKeepsUnknown(t *testing.T) {
	dir := moduleDir(t, t.TempDir())

	s := New(Config{
		DataDir:  t.TempDir(),
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	fs := []findings.Finding{goFinding("GO-2026-6860", "golang.org/x/net")}
	ran, err := s.Enrich(context.Background(), dir, fs)
	if !ran || err == nil || !strings.Contains(err.Error(), ErrGoUnavailable.Error()) {
		t.Fatalf("ran=%v err=%v, want ran and ErrGoUnavailable", ran, err)
	}
	if fs[0].Reachability != findings.ReachabilityUnknown {
		t.Errorf("reachability = %q, want unknown", fs[0].Reachability)
	}
}

// TestDisabledDoesNothing proves the opt-in default: the workspace is a valid
// Go module, so only the setting prevents the analysis.
func TestDisabledDoesNothing(t *testing.T) {
	dir := moduleDir(t, t.TempDir())

	called := false
	s := New(Config{
		DataDir:  t.TempDir(),
		LookPath: func(string) (string, error) { return "/usr/bin/go", nil },
		Run: func(context.Context, string) (map[string]map[string]bool, error) {
			called = true
			return nil, nil
		},
	})
	fs := []findings.Finding{goFinding("GO-2026-6860", "golang.org/x/net")}
	ran, err := s.Enrich(context.Background(), dir, fs)
	if ran || err != nil || called {
		t.Fatalf("ran=%v err=%v called=%v, want no analysis with the setting off", ran, err, called)
	}
	if fs[0].Reachability != "" {
		t.Errorf("reachability = %q, want untouched", fs[0].Reachability)
	}
}

// TestChildEnvAllowlist proves the child gets only the toolchain's environment:
// no inherited secrets, and behaviour pinned.
func TestChildEnvAllowlist(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin", "HOME=/home/u", "TMPDIR=/tmp",
		"GOPATH=/go", "GOMODCACHE=/go/pkg/mod", "GOCACHE=/go/cache",
		"GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org",
		"AWS_SECRET_ACCESS_KEY=secret", "GITHUB_TOKEN=secret",
		"BASTION_SECRET=secret", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=auto",
		"GOWORK=/tmp/go.work",
	}
	env := childEnv(parent)

	want := map[string]string{
		"PATH": "/usr/bin", "HOME": "/home/u", "TMPDIR": "/tmp",
		"GOPATH": "/go", "GOMODCACHE": "/go/pkg/mod", "GOCACHE": "/go/cache",
		"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
		"GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOWORK": "off",
		"GOFLAGS": "", "GOENV": "off", "GOTELEMETRY": "off",
	}
	got := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		got[key] = value
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	for _, key := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "BASTION_SECRET"} {
		if _, ok := got[key]; ok {
			t.Errorf("%s leaked into the child environment", key)
		}
	}
	if len(got) != len(want) {
		t.Errorf("environment has %d entries, want %d: %v", len(got), len(want), env)
	}
	if !slices.IsSorted(env) {
		t.Errorf("environment is not deterministic: %v", env)
	}
}

// TestEnrichTimeoutKillsChild proves the deadline bounds a hung analyzer and
// the finding stays unknown. The child is `sleep`, standing in for a go
// toolchain that ignores its context.
func TestEnrichTimeoutKillsChild(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep executable to stand in for a hung analyzer")
	}
	dir := moduleDir(t, t.TempDir())

	s := New(Config{
		DataDir:    t.TempDir(),
		LookPath:   func(string) (string, error) { return "/usr/bin/go", nil },
		Executable: sleep,
		ChildArgs:  func(string) []string { return []string{"60"} },
		Timeout:    300 * time.Millisecond,
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	fs := []findings.Finding{goFinding("GO-2026-6860", "golang.org/x/net")}
	start := time.Now()
	ran, err := s.Enrich(context.Background(), dir, fs)
	elapsed := time.Since(start)

	if !ran || err == nil {
		t.Fatalf("ran=%v err=%v, want a timeout error", ran, err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("enrich took %v, want the child killed at the deadline", elapsed)
	}
	if fs[0].Reachability != findings.ReachabilityUnknown {
		t.Errorf("reachability = %q, want unknown after a timeout", fs[0].Reachability)
	}
}

// TestModuleDirsBounds proves the walk ignores vendor trees and symlinked
// module files, and stops at the module cap.
func TestModuleDirsBounds(t *testing.T) {
	root := t.TempDir()
	moduleDir(t, root, "app")
	moduleDir(t, root, "vendor", "dep")
	moduleDir(t, root, ".hidden")

	outside := t.TempDir()
	moduleDir(t, outside, "escape")
	if err := os.Symlink(filepath.Join(outside, "escape"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	dirs := moduleDirs(root)
	if len(dirs) != 1 || filepath.Base(dirs[0]) != "app" {
		t.Fatalf("module dirs = %v, want only app", dirs)
	}
}
