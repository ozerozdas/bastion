package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/update"
)

// updateTestChecker returns a checker backed by an httptest server that counts
// requests, so the handler tests can prove that an unset or off consent sends
// nothing.
func updateTestChecker(t *testing.T, hits *atomic.Int32) *update.Checker {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "/ozerozdas/bastion/releases/tag/v0.2.0")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)

	return update.New(update.Config{
		CurrentVersion: "v0.1.0",
		DataDir:        t.TempDir(),
		CacheDir:       t.TempDir(),
		BaseURL:        server.URL,
		Getenv:         func(string) string { return "" },
		Executable:     func() (string, error) { return "/home/me/.local/bin/bastion", nil },
		GOOS:           "darwin",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// doJSON sends a same-origin mutating request with the CSRF header (unless the
// caller overrides the headers).
func (ts *testServer) doJSON(t *testing.T, method, path, body string, cookie *http.Cookie, csrf bool) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, ts.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-Bastion", "1")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readUpdateStatus(t *testing.T, resp *http.Response) gen.UpdateStatus {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var status gen.UpdateStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode update status: %v", err)
	}
	return status
}

func TestGetUpdateStatusWithUnsetConsentMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithUpdate(t, nil, updateTestChecker(t, &hits))
	cookie := ts.login(t)

	status := readUpdateStatus(t, ts.do(t, http.MethodGet, "/api/update", withCookie(cookie)))

	if got, want := status.Consent, gen.Unset; got != want {
		t.Errorf("consent = %q, want %q", got, want)
	}
	if status.UpdateAvailable {
		t.Error("update_available = true with no cached check")
	}
	if status.Latest != nil {
		t.Errorf("latest = %q, want absent", *status.Latest)
	}
	if got, want := status.Current, "v0.1.0"; got != want {
		t.Errorf("current = %q, want %q", got, want)
	}
	if status.Disabled {
		t.Error("disabled = true for a release build without CI or the env switch")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("release check requests = %d, want 0 with unset consent", got)
	}
}

// A dev build cannot check, so the UI must not ask (disabled: true).
func TestGetUpdateStatusReportsDisabledForDevBuild(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	checker := update.New(update.Config{
		CurrentVersion: "dev",
		DataDir:        t.TempDir(),
		CacheDir:       t.TempDir(),
		BaseURL:        server.URL,
		Getenv:         func(string) string { return "" },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ts := newTestServerWithUpdate(t, nil, checker)
	cookie := ts.login(t)

	status := readUpdateStatus(t, ts.do(t, http.MethodGet, "/api/update", withCookie(cookie)))
	if !status.Disabled {
		t.Error("disabled = false for a dev build")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("release check requests = %d, want 0", got)
	}
}

func TestSetUpdateConsent(t *testing.T) {
	var hits atomic.Int32
	checker := updateTestChecker(t, &hits)
	ts := newTestServerWithUpdate(t, nil, checker)
	cookie := ts.login(t)

	on := readUpdateStatus(t, ts.doJSON(t, http.MethodPut, "/api/update/consent", `{"enabled":true}`, cookie, true))
	if got, want := on.Consent, gen.On; got != want {
		t.Errorf("consent after enable = %q, want %q", got, want)
	}
	if got := checker.Consent(); got != update.ConsentOn {
		t.Errorf("stored consent = %q, want on", got)
	}

	off := readUpdateStatus(t, ts.doJSON(t, http.MethodPut, "/api/update/consent", `{"enabled":false}`, cookie, true))
	if got, want := off.Consent, gen.Off; got != want {
		t.Errorf("consent after disable = %q, want %q", got, want)
	}
	if got := checker.Consent(); got != update.ConsentOff {
		t.Errorf("stored consent = %q, want off", got)
	}
}

func TestSetUpdateConsentRequiresCSRFAndBody(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithUpdate(t, nil, updateTestChecker(t, &hits))
	cookie := ts.login(t)

	forbidden := ts.doJSON(t, http.MethodPut, "/api/update/consent", `{"enabled":true}`, cookie, false)
	if forbidden.StatusCode != http.StatusForbidden {
		t.Errorf("PUT without X-Bastion = %d, want %d", forbidden.StatusCode, http.StatusForbidden)
	}

	badRequest := ts.doJSON(t, http.MethodPut, "/api/update/consent", ``, cookie, true)
	if badRequest.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT without a body = %d, want %d", badRequest.StatusCode, http.StatusBadRequest)
	}
	problem := readProblem(t, badRequest)
	if problem.Status != http.StatusBadRequest {
		t.Errorf("problem.status = %d, want %d", problem.Status, http.StatusBadRequest)
	}
}

func TestGetUpdateStatusReportsCachedRelease(t *testing.T) {
	var hits atomic.Int32
	checker := updateTestChecker(t, &hits)
	if err := checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}
	// Seed the cache through the real check path, so the handler test does not
	// depend on the package's file format.
	checker.CheckNow(context.Background())
	if got := hits.Load(); got != 1 {
		t.Fatalf("seed check requests = %d, want 1", got)
	}

	ts := newTestServerWithUpdate(t, nil, checker)
	cookie := ts.login(t)

	status := readUpdateStatus(t, ts.do(t, http.MethodGet, "/api/update", withCookie(cookie)))

	if got, want := status.Consent, gen.On; got != want {
		t.Errorf("consent = %q, want %q", got, want)
	}
	if !status.UpdateAvailable {
		t.Error("update_available = false, want true")
	}
	if status.Latest == nil || *status.Latest != "v0.2.0" {
		t.Errorf("latest = %v, want v0.2.0", status.Latest)
	}
	if status.Command == nil || *status.Command == "" {
		t.Errorf("command = %v, want the install hint", status.Command)
	}
	if status.ReleaseUrl == nil || *status.ReleaseUrl != "https://github.com/ozerozdas/bastion/releases/tag/v0.2.0" {
		t.Errorf("release_url = %v, want the release page", status.ReleaseUrl)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests after a fresh cache = %d, want 1", got)
	}
}

func TestGetUpdateStatusRequiresSession(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithUpdate(t, nil, updateTestChecker(t, &hits))

	resp := ts.do(t, http.MethodGet, "/api/update", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
