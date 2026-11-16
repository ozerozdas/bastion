package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/opengrep"
)

// readSASTStatus decodes one /api/sast response.
func readSASTStatus(t *testing.T, resp *http.Response) gen.SASTStatus {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var status gen.SASTStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode SAST status: %v", err)
	}
	return status
}

func TestSASTOffByDefault(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	status := readSASTStatus(t, ts.do(t, http.MethodGet, "/api/sast", withCookie(cookie)))
	if status.Enabled {
		t.Error("enabled = true on a fresh install")
	}
	if status.State != gen.NotInstalled {
		t.Errorf("state = %q, want not_installed", status.State)
	}
	if status.Version != opengrep.Version {
		t.Errorf("version = %q, want %q", status.Version, opengrep.Version)
	}
	if status.Installing {
		t.Error("installing = true on a fresh install")
	}
}

func TestSetSASTEnabledStartsInstall(t *testing.T) {
	var calls int
	service := opengrep.New(opengrep.Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Spawn:      func(f func()) { f() },
		Install: func(context.Context) error {
			calls++
			return nil
		},
	})
	ts := newTestServerWithConfig(t, nil, nil, nil, nil, service)
	cookie := ts.login(t)

	status := readSASTStatus(t, ts.doJSON(t, http.MethodPut, "/api/sast", `{"enabled":true}`, cookie, true))
	if !status.Enabled {
		t.Error("enabled = false after opting in")
	}
	if calls != 1 {
		t.Fatalf("install calls = %d, want 1", calls)
	}
	if status.Installing {
		t.Error("installing = true after the inline install finished")
	}
}

func TestSetSASTEnabledReportsInstallFailure(t *testing.T) {
	service := opengrep.New(opengrep.Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Spawn:      func(f func()) { f() },
		Install:    func(context.Context) error { return errors.New("network is down") },
	})
	ts := newTestServerWithConfig(t, nil, nil, nil, nil, service)
	cookie := ts.login(t)

	status := readSASTStatus(t, ts.doJSON(t, http.MethodPut, "/api/sast", `{"enabled":true}`, cookie, true))
	if status.InstallError == nil || *status.InstallError != "network is down" {
		t.Fatalf("install_error = %v, want the failure", status.InstallError)
	}
	if status.State != gen.NotInstalled {
		t.Fatalf("state = %q, want not_installed", status.State)
	}
}

func TestSetSASTEnabledRejectsBadBody(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	for _, body := range []string{``, `{"enabled":"yes"}`} {
		resp := ts.doJSON(t, http.MethodPut, "/api/sast", body, cookie, true)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}
