//go:build govulnreal

// This test runs the real govulncheck through the child-process path, so it
// needs `go` on PATH and network access to proxy.golang.org and vuln.go.dev.
// Run it with:
//
//	go test -tags govulnreal ./internal/scanners/govulncheck
package govulncheck

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
)

// TestRealGovulncheckClassifiesFixture is the end-to-end Done-when check: the
// fixture calls golang.org/x/net/html.Parse (GO-2026-6860) and only imports
// golang.org/x/net/idna (GO-2026-5026), so the first must be reachable and the
// second unreachable.
//
// The analysis runs in a child process, so the test builds bastion first and
// points the service at it: the test binary has no internal-govulncheck
// subcommand.
func TestRealGovulncheckClassifiesFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("real govulncheck downloads modules and the vulnerability database")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go executable on PATH")
	}

	binary := filepath.Join(t.TempDir(), "bastion")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bastion")
	build.Dir = filepath.Join("..", "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build bastion: %v\n%s", err, out)
	}

	dir, err := filepath.Abs(filepath.Join("testdata", "fixture"))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}

	s := New(Config{
		DataDir:    t.TempDir(),
		Executable: binary,
		Timeout:    10 * time.Minute,
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	fs := []findings.Finding{
		goFinding("GO-2026-6860", "golang.org/x/net"),
		goFinding("GO-2026-5026", "golang.org/x/net"),
	}
	ran, err := s.Enrich(context.Background(), dir, fs)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !ran {
		t.Fatal("enrich did not run on the fixture module")
	}
	if fs[0].Reachability != findings.ReachabilityReachable {
		t.Errorf("GO-2026-6860 (html.Parse called) = %q, want reachable", fs[0].Reachability)
	}
	if fs[1].Reachability != findings.ReachabilityUnreachable {
		t.Errorf("GO-2026-5026 (idna uncalled) = %q, want unreachable", fs[1].Reachability)
	}
}
