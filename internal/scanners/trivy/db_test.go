package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubUpdater stands in for the real download: it counts attempts, optionally
// blocks until the test releases it, and writes Trivy's metadata file on
// success. No test touches the network.
type stubUpdater struct {
	mu        sync.Mutex
	calls     int
	err       error
	updatedAt time.Time
	release   chan struct{}

	started chan struct{}
}

func newStubUpdater() *stubUpdater {
	return &stubUpdater{
		updatedAt: time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC),
		release:   make(chan struct{}),
		started:   make(chan struct{}, 4),
	}
}

func (s *stubUpdater) update(_ context.Context, cacheDir string) error {
	s.mu.Lock()
	s.calls++
	err := s.err
	updatedAt := s.updatedAt
	release := s.release
	s.mu.Unlock()

	s.started <- struct{}{}
	if release != nil {
		<-release
	}
	if err != nil {
		return err
	}

	dbDir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dbDir, 0o750); err != nil {
		return err
	}
	body := []byte(`{"UpdatedAt":"` + updatedAt.Format(time.RFC3339) + `"}`)
	return os.WriteFile(filepath.Join(dbDir, metadataFile), body, 0o600)
}

func (s *stubUpdater) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *stubUpdater) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubUpdater) timestamp() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updatedAt
}

// waitStarted blocks until the updater is running one attempt.
func (s *stubUpdater) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-s.started:
	case <-time.After(2 * time.Second):
		t.Fatal("updater did not start")
	}
}

// waitForState polls the manager until it reports want.
func waitForState(t *testing.T, m *Manager, want DBState) DBStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		status := m.Status()
		if status.State == want {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %q (error %q), want %q", status.State, status.Error, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestManagerMissingThenReady(t *testing.T) {
	updater := newStubUpdater()
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	if got := m.Status(); got.State != DBMissing {
		t.Fatalf("state = %q, want %q before any download", got.State, DBMissing)
	}

	status := m.StartDownload()
	if status.State != DBDownloading {
		t.Fatalf("StartDownload state = %q, want %q", status.State, DBDownloading)
	}
	if status.Trigger != triggerUser {
		t.Errorf("trigger = %q, want %q", status.Trigger, triggerUser)
	}

	updater.waitStarted(t)
	if got := m.Status(); got.State != DBDownloading || got.Trigger != triggerUser {
		t.Errorf("status during download = %+v, want downloading by user", got)
	}

	close(updater.release)
	ready := waitForState(t, m, DBReady)
	if ready.UpdatedAt == nil || !ready.UpdatedAt.Equal(updater.timestamp()) {
		t.Errorf("updated_at = %v, want %v", ready.UpdatedAt, updater.timestamp())
	}
	if ready.Trigger != "" {
		t.Errorf("trigger = %q, want empty for a ready DB", ready.Trigger)
	}
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1", got)
	}
}

func TestStartDownloadIsSingleFlight(t *testing.T) {
	updater := newStubUpdater()
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	m.StartDownload()
	updater.waitStarted(t)

	second := m.StartDownload()
	if second.State != DBDownloading {
		t.Errorf("second StartDownload state = %q, want %q", second.State, DBDownloading)
	}
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1 while a download is in flight", got)
	}

	close(updater.release)
	waitForState(t, m, DBReady)
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1", got)
	}
}

// A scan that starts while the user's download is running must wait for it and
// must not start a second one.
func TestEnsureReadyJoinsUserDownload(t *testing.T) {
	updater := newStubUpdater()
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	m.StartDownload()
	updater.waitStarted(t)

	errs := make(chan error, 1)
	go func() { errs <- m.EnsureReady(t.Context()) }()

	select {
	case err := <-errs:
		t.Fatalf("EnsureReady returned before the download finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(updater.release)
	if err := <-errs; err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1", got)
	}
}

func TestEnsureReadyDownloadsWhenMissing(t *testing.T) {
	updater := newStubUpdater()
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	errs := make(chan error, 1)
	go func() { errs <- m.EnsureReady(t.Context()) }()
	updater.waitStarted(t)

	if got := m.Status(); got.State != DBDownloading || got.Trigger != triggerScan {
		t.Errorf("status = %+v, want downloading by scan", got)
	}

	close(updater.release)
	if err := <-errs; err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	waitForState(t, m, DBReady)
	if got := updater.count(); got != 1 {
		t.Errorf("updater calls = %d, want 1", got)
	}
}

func TestEnsureReadyContextCancelWhileWaiting(t *testing.T) {
	updater := newStubUpdater()
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	m.StartDownload()
	updater.waitStarted(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := m.EnsureReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EnsureReady error = %v, want context.DeadlineExceeded", err)
	}

	close(updater.release)
	waitForState(t, m, DBReady)
}

func TestFailedDownloadKeepsErrorThenRetrySucceeds(t *testing.T) {
	updater := newStubUpdater()
	updater.setErr(errors.New("registry unreachable"))
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	m.StartDownload()
	updater.waitStarted(t)
	close(updater.release)

	failed := waitForState(t, m, DBFailed)
	if failed.Error == "" {
		t.Error("failed status carries no error detail")
	}
	if failed.Trigger != triggerUser {
		t.Errorf("trigger = %q, want %q", failed.Trigger, triggerUser)
	}

	updater.setErr(nil)
	if got := m.StartDownload(); got.State != DBDownloading {
		t.Fatalf("retry state = %q, want %q", got.State, DBDownloading)
	}
	waitForState(t, m, DBReady)
	if got := updater.count(); got != 2 {
		t.Errorf("updater calls = %d, want 2", got)
	}
	if got := m.Status().Error; got != "" {
		t.Errorf("error = %q after a successful retry, want empty", got)
	}
}

func TestEnsureReadyReportsFailedDownload(t *testing.T) {
	updater := newStubUpdater()
	updater.setErr(errors.New("registry unreachable"))
	// No blocking: EnsureReady runs the attempt itself.
	updater.release = nil
	m := newManagerWithUpdater(t.TempDir(), updater.update)
	t.Cleanup(m.Close)

	err := m.EnsureReady(t.Context())
	if err == nil {
		t.Fatal("EnsureReady succeeded with a failing updater")
	}
	if !strings.Contains(err.Error(), "registry unreachable") {
		t.Errorf("error = %q, want it to carry the updater's error", err)
	}
}
