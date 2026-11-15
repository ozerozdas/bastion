package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// feedServer serves a feed and counts every request, so a test can prove that
// an off setting sends nothing.
func feedServer(t *testing.T, hits *atomic.Int32, body []byte, status *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if status != nil && status.Load() != 0 {
			w.WriteHeader(int(status.Load()))
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// newTestService wires a service against the fake feed with an inline spawner,
// so Status() finishes any refresh before it returns.
func newTestService(t *testing.T, url string, now func() time.Time) *Service {
	t.Helper()
	return New(Config{
		DataDir:  t.TempDir(),
		CacheDir: t.TempDir(),
		URL:      url,
		Now:      now,
		Version:  "test",
		Spawn:    func(f func()) { f() },
	})
}

func TestOffMeansNoRequest(t *testing.T) {
	var hits atomic.Int32
	server := feedServer(t, &hits, gzipFeed(t, fixtureFeed), nil)
	service := newTestService(t, server.URL, time.Now)

	status := service.Status()
	if status.Enabled {
		t.Fatal("a fresh install must have EPSS off")
	}
	if _, ok := service.Lookup("CVE-2021-44228"); ok {
		t.Error("Lookup returned a score while the feed is off")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 with the feed off", got)
	}
}

func TestEnableDownloadsAndLooksUp(t *testing.T) {
	var hits atomic.Int32
	server := feedServer(t, &hits, gzipFeed(t, fixtureFeed), nil)
	service := newTestService(t, server.URL, time.Now)

	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	service.Status()

	status := service.Snapshot()
	if !status.Enabled {
		t.Fatal("Snapshot reports the feed off after enabling it")
	}
	if status.Count != 2 {
		t.Errorf("count = %d, want 2", status.Count)
	}
	if status.ScoreDate != "2026-11-15T12:03:04Z" {
		t.Errorf("score date = %q", status.ScoreDate)
	}
	if status.LastRefresh.IsZero() {
		t.Error("last refresh is zero after a successful download")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}

	score, ok := service.Lookup("CVE-2021-44228")
	if !ok {
		t.Fatal("Lookup missed a scored CVE")
	}
	if score.Score != 0.99999 || score.Percentile != 1.0 {
		t.Errorf("score = %+v, want 0.99999 / 1.0", score)
	}
	if _, ok := service.Lookup("CVE-1999-0001"); ok {
		t.Error("Lookup returned a score for an unscored CVE")
	}

	// Disabling stops lookups and every future request.
	if err := service.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if _, ok := service.Lookup("CVE-2021-44228"); ok {
		t.Error("Lookup returned a score after the feed was turned off")
	}
}

func TestRefreshFollowsDailyBudget(t *testing.T) {
	var hits atomic.Int32
	server := feedServer(t, &hits, gzipFeed(t, fixtureFeed), nil)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, server.URL, func() time.Time { return now })

	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	service.Status()
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests after first refresh = %d, want 1", got)
	}

	now = now.Add(23 * time.Hour)
	service.Status()
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests after 23h = %d, want 1 (budget holds)", got)
	}

	now = now.Add(2 * time.Hour)
	service.Status()
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests after 25h = %d, want 2", got)
	}
}

func TestFailedRefreshKeepsCache(t *testing.T) {
	var hits atomic.Int32
	var status atomic.Int32
	server := feedServer(t, &hits, gzipFeed(t, fixtureFeed), &status)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, server.URL, func() time.Time { return now })

	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	service.Status()
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}

	status.Store(http.StatusInternalServerError)
	now = now.Add(25 * time.Hour)
	service.Status()

	snapshot := service.Snapshot()
	if snapshot.Error == "" {
		t.Fatal("a failed refresh must be reported in Status.Error")
	}
	if snapshot.Count != 2 {
		t.Errorf("count = %d, want the previous cache's 2", snapshot.Count)
	}
	if _, ok := service.Lookup("CVE-2021-44228"); !ok {
		t.Error("Lookup lost the cached scores after a failed refresh")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestRefreshWhileOffMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	server := feedServer(t, &hits, gzipFeed(t, fixtureFeed), nil)
	service := newTestService(t, server.URL, time.Now)

	// A disabled service must not download even when Refresh is called.
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh while off: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 while off", got)
	}
}
