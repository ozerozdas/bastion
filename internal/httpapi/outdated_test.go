package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/depsdev"
)

// outdatedTestService is a real service with a throwaway data directory. The
// handler never calls the network, so the default base URL is never used.
func outdatedTestService(t *testing.T) *depsdev.Service {
	t.Helper()
	return depsdev.New(depsdev.Config{DataDir: t.TempDir(), Version: "test"})
}

func readOutdatedStatus(t *testing.T, resp *http.Response) gen.OutdatedStatus {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var status gen.OutdatedStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode outdated status: %v", err)
	}
	return status
}

func TestOutdatedOffByDefault(t *testing.T) {
	ts := newTestServerWithOutdated(t, outdatedTestService(t))
	cookie := ts.login(t)

	status := readOutdatedStatus(t, ts.do(t, http.MethodGet, "/api/outdated", withCookie(cookie)))
	if status.Enabled {
		t.Error("enabled = true on a fresh install")
	}
}

func TestSetOutdatedEnabled(t *testing.T) {
	ts := newTestServerWithOutdated(t, outdatedTestService(t))
	cookie := ts.login(t)

	enabled := readOutdatedStatus(t, ts.doJSON(t, http.MethodPut, "/api/outdated", `{"enabled":true}`, cookie, true))
	if !enabled.Enabled {
		t.Error("enabled = false after opting in")
	}

	// The setting is stored, not just echoed.
	status := readOutdatedStatus(t, ts.do(t, http.MethodGet, "/api/outdated", withCookie(cookie)))
	if !status.Enabled {
		t.Error("enabled = false on the next read")
	}

	off := readOutdatedStatus(t, ts.doJSON(t, http.MethodPut, "/api/outdated", `{"enabled":false}`, cookie, true))
	if off.Enabled {
		t.Error("enabled = true after opting out")
	}
}

func TestOutdatedWithoutServiceIs500(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/outdated", withCookie(cookie))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}
