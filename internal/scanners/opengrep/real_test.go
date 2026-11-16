//go:build opengrepreal

// This test downloads the pinned Opengrep binary and rule set and runs the real
// scanner over a tiny fixture. It needs network access to GitHub. Run it with:
//
//	go test -tags opengrepreal ./internal/scanners/opengrep -run TestReal -v
package opengrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
)

// evalIssue is a file the eval-detected rule matches.
const evalIssue = "def run(user_input):\n    return eval(user_input)\n"

// TestRealOpengrepFindsEval is the end-to-end Done-when check: a fixture with
// eval(user_input) must produce a sast finding from the pinned rule set, with
// the rules-root prefix stripped from the rule id. The fixture is copied to a
// workspace that also holds .git, node_modules and vendor trees, so the
// --exclude patterns are checked against a real scan: a file named legit.py
// must still be scanned while those directories are skipped.
func TestRealOpengrepFindsEval(t *testing.T) {
	if testing.Short() {
		t.Skip("real opengrep downloads the binary and rule set")
	}

	service := New(Config{
		ModulesDir: t.TempDir(),
		Version:    "test",
		Timeout:    5 * time.Minute,
	})
	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", "fixture"))); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	// The excluded directories hold the same issue. Their findings must not
	// appear: the flag is a gitignore-style glob, so ".git" must match the
	// directory and not a name that merely contains "git", such as legit.py.
	for _, excluded := range []string{".git", "node_modules", "vendor"} {
		nested := filepath.Join(dir, excluded)
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatalf("create %s: %v", excluded, err)
		}
		if err := os.WriteFile(filepath.Join(nested, "evil.py"), []byte(evalIssue), 0o600); err != nil {
			t.Fatalf("write %s/evil.py: %v", excluded, err)
		}
	}

	scanner := NewScanner(service)
	raw, err := scanner.Scan(t.Context(), &sources.Workspace{Dir: dir}, scanners.Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fs, _, err := scanner.Normalize(raw, findings.Asset{
		ID:          1,
		Kind:        findings.AssetKindPath,
		DisplayName: "fixture",
		Ref:         dir,
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(raw.Warnings) > 0 {
		t.Logf("warnings: %v", raw.Warnings)
	}

	locations := make(map[string]findings.Finding, len(fs))
	for _, f := range fs {
		if f.RuleID != "python.lang.security.audit.eval-detected" {
			continue
		}
		locations[f.Location] = f
	}
	for _, want := range []string{"app.py:2", "legit.py:2"} {
		f, ok := locations[want]
		if !ok {
			t.Fatalf("no eval-detected finding at %s; got %+v", want, fs)
		}
		if f.Type != findings.TypeSAST {
			t.Fatalf("type = %q, want sast", f.Type)
		}
		if f.Severity != findings.SeverityMedium {
			t.Fatalf("severity = %q, want medium", f.Severity)
		}
		if f.Scanner != Name {
			t.Fatalf("scanner = %q, want %q", f.Scanner, Name)
		}
	}
	for _, f := range fs {
		if strings.HasPrefix(f.Location, ".git/") ||
			strings.HasPrefix(f.Location, "node_modules/") ||
			strings.HasPrefix(f.Location, "vendor/") {
			t.Fatalf("finding in an excluded directory: %+v", f)
		}
	}
}
