package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
)

// trivyStubUpdater stands in for the DB download: it counts attempts, blocks
// until the test releases it and writes Trivy's metadata file on success. No
// handler test reaches the network.
type trivyStubUpdater struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
	started chan struct{}
}

func newTrivyStubUpdater() *trivyStubUpdater {
	return &trivyStubUpdater{
		release: make(chan struct{}),
		started: make(chan struct{}, 4),
	}
}

func (u *trivyStubUpdater) update(_ context.Context, cacheDir string) error {
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()

	u.started <- struct{}{}
	<-u.release

	dbDir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dbDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dbDir, "metadata.json"),
		[]byte(`{"UpdatedAt":"2026-11-01T12:00:00Z"}`), 0o600)
}

func (u *trivyStubUpdater) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func (u *trivyStubUpdater) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-u.started:
	case <-time.After(2 * time.Second):
		t.Fatal("updater did not start")
	}
}

// readTrivyDBStatus decodes the endpoint's body and asserts the status code.
func readTrivyDBStatus(t *testing.T, resp *http.Response, wantStatus int) gen.TrivyDBStatus {
	t.Helper()

	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	var status gen.TrivyDBStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode trivy DB status: %v", err)
	}
	return status
}

func TestGetTrivyDBReportsMissing(t *testing.T) {
	updater := newTrivyStubUpdater()
	manager := trivy.NewManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(manager.Close)
	ts := newTestServerWithTrivyDB(t, manager)
	cookie := ts.login(t)

	status := readTrivyDBStatus(t, ts.do(t, http.MethodGet, "/api/trivy-db", withCookie(cookie)), http.StatusOK)

	if got, want := status.State, gen.TrivyDBStateMissing; got != want {
		t.Errorf("state = %q, want %q", got, want)
	}
	if status.UpdatedAt != nil {
		t.Errorf("updated_at = %v, want absent for a missing DB", status.UpdatedAt)
	}
	if status.Trigger != nil {
		t.Errorf("trigger = %q, want absent before any download", *status.Trigger)
	}
	if got := updater.count(); got != 0 {
		t.Errorf("updater calls = %d, want 0 from a read", got)
	}
}

func TestDownloadTrivyDBStartsOneDownload(t *testing.T) {
	updater := newTrivyStubUpdater()
	manager := trivy.NewManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(manager.Close)
	ts := newTestServerWithTrivyDB(t, manager)
	cookie := ts.login(t)

	started := readTrivyDBStatus(t,
		ts.doJSON(t, http.MethodPost, "/api/trivy-db/download", "", cookie, true), http.StatusAccepted)
	if got, want := started.State, gen.TrivyDBStateDownloading; got != want {
		t.Errorf("state = %q, want %q", got, want)
	}
	if started.Trigger == nil || *started.Trigger != gen.TrivyDBStatusTriggerUser {
		t.Errorf("trigger = %v, want %q", started.Trigger, gen.TrivyDBStatusTriggerUser)
	}

	updater.waitStarted(t)

	// A second call joins the download in flight instead of starting another.
	second := readTrivyDBStatus(t,
		ts.doJSON(t, http.MethodPost, "/api/trivy-db/download", "", cookie, true), http.StatusAccepted)
	if got, want := second.State, gen.TrivyDBStateDownloading; got != want {
		t.Errorf("second state = %q, want %q", got, want)
	}
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1 while a download is in flight", got)
	}

	close(updater.release)

	deadline := time.Now().Add(2 * time.Second)
	for {
		status := readTrivyDBStatus(t, ts.do(t, http.MethodGet, "/api/trivy-db", withCookie(cookie)), http.StatusOK)
		if status.State == gen.TrivyDBStateReady {
			if status.UpdatedAt == nil {
				t.Error("updated_at is absent for a ready DB")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %q, want %q", status.State, gen.TrivyDBStateReady)
		}
		time.Sleep(time.Millisecond)
	}
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1", got)
	}
}

func TestDownloadTrivyDBRequiresCSRF(t *testing.T) {
	updater := newTrivyStubUpdater()
	manager := trivy.NewManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(manager.Close)
	ts := newTestServerWithTrivyDB(t, manager)
	cookie := ts.login(t)

	resp := ts.doJSON(t, http.MethodPost, "/api/trivy-db/download", "", cookie, false)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without X-Bastion: status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	readProblem(t, resp)
	if got := updater.count(); got != 0 {
		t.Errorf("updater calls = %d, want 0 for a rejected request", got)
	}
}

// A Server built without a manager answers 500, like the other service-backed
// routes.
func TestTrivyDBUnavailableWithoutManager(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	get := ts.do(t, http.MethodGet, "/api/trivy-db", withCookie(cookie))
	if get.StatusCode != http.StatusInternalServerError {
		t.Errorf("GET status = %d, want %d", get.StatusCode, http.StatusInternalServerError)
	}
	readProblem(t, get)

	post := ts.doJSON(t, http.MethodPost, "/api/trivy-db/download", "", cookie, true)
	if post.StatusCode != http.StatusInternalServerError {
		t.Errorf("POST status = %d, want %d", post.StatusCode, http.StatusInternalServerError)
	}
	readProblem(t, post)
}
