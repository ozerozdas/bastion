package securitynews

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const rssFixture = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example Security</title>
    <item>
      <title>Critical flaw &amp; a patch</title>
      <link>https://example.com/advisory?id=1</link>
      <pubDate>Sun, 15 Nov 2026 12:00:00 GMT</pubDate>
      <description><![CDATA[<p>An <strong>important</strong> advisory.</p><script>alert(1)</script>]]></description>
    </item>
    <item>
      <title>Older item</title>
      <link>https://example.com/advisory?id=2</link>
      <pubDate>Sat, 14 Nov 2026 09:00:00 GMT</pubDate>
      <description>Second summary.</description>
    </item>
    <item>
      <title>Hostile link</title>
      <link>javascript:alert(1)</link>
      <description>Should be dropped.</description>
    </item>
  </channel>
</rss>`

const atomFixture = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example Atom</title>
  <entry>
    <title>Atom research</title>
    <link rel="alternate" type="text/html" href="https://example.org/research"/>
    <published>2026-11-16T08:30:00Z</published>
    <summary type="html">&lt;b&gt;A&lt;/b&gt; summary &amp;amp; more.</summary>
  </entry>
</feed>`

// testServer serves body and counts hits.
func testServer(t *testing.T, body string, status *atomic.Int32, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if status != nil && status.Load() != 0 {
			w.WriteHeader(int(status.Load()))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func newTestService(t *testing.T, sources []Source, now func() time.Time) *Service {
	t.Helper()
	return New(Config{
		DataDir: t.TempDir(),
		Sources: sources,
		Now:     now,
		Version: "test",
	})
}

func TestOffMeansNoRequest(t *testing.T) {
	var hits atomic.Int32
	server := testServer(t, rssFixture, nil, &hits)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, time.Now)

	feed := service.Feed(context.Background())
	if feed.Enabled {
		t.Fatal("a fresh install must have Security News off")
	}
	if len(feed.Items) != 0 {
		t.Fatalf("items = %d, want 0 while off", len(feed.Items))
	}
	if len(feed.Sources) != 1 || !feed.Sources[0].Enabled {
		t.Fatalf("sources = %+v, want the recommended source preselected", feed.Sources)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 with the feature off", got)
	}
}

func TestEnabledFetchesAndCaches(t *testing.T) {
	var hits atomic.Int32
	server := testServer(t, rssFixture, nil, &hits)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, func() time.Time { return now })

	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	feed := service.Feed(context.Background())
	if !feed.Enabled {
		t.Fatal("feed reports off after enabling it")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	// The javascript: link is dropped and HTML is stripped.
	if len(feed.Items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(feed.Items), feed.Items)
	}
	if feed.Items[0].Title != "Critical flaw & a patch" {
		t.Errorf("title = %q", feed.Items[0].Title)
	}
	if feed.Items[0].Summary != "An important advisory." {
		t.Errorf("summary = %q", feed.Items[0].Summary)
	}
	if !feed.Items[0].Published.Equal(time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("published = %v", feed.Items[0].Published)
	}
	if feed.Items[0].Source != "One" {
		t.Errorf("source = %q", feed.Items[0].Source)
	}

	// A second call inside the TTL is served from memory.
	service.Feed(context.Background())
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 inside the TTL", got)
	}

	// Past the TTL the source is fetched again.
	now = now.Add(DefaultTTL + time.Minute)
	service.Feed(context.Background())
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 after the TTL", got)
	}
}

func TestOneFailedSourceDoesNotHideTheOthers(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusInternalServerError)
	broken := testServer(t, rssFixture, &status, nil)
	healthy := testServer(t, atomFixture, nil, nil)

	service := newTestService(t, []Source{
		{ID: "broken", Name: "Broken", URL: broken.URL, Recommended: true},
		{ID: "healthy", Name: "Healthy", URL: healthy.URL, Recommended: true},
	}, time.Now)
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	feed := service.Feed(context.Background())
	if len(feed.Items) != 1 || feed.Items[0].Source != "Healthy" {
		t.Fatalf("items = %+v, want the healthy source's item", feed.Items)
	}
	var brokenError string
	for _, source := range feed.Sources {
		if source.ID == "broken" {
			brokenError = source.Error
		}
	}
	if brokenError == "" {
		t.Fatal("the broken source did not report an error")
	}
}

func TestAtomIsParsed(t *testing.T) {
	items, err := parseFeed([]byte(atomFixture))
	if err != nil {
		t.Fatalf("parseFeed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].Link != "https://example.org/research" {
		t.Errorf("link = %q", items[0].Link)
	}
	if got := plainText(items[0].Summary, MaxSummaryRunes); got != "A summary & more." {
		t.Errorf("summary = %q", got)
	}
}

func TestSettingsPersist(t *testing.T) {
	source := Source{ID: "kept", Name: "Kept", URL: "https://example.com/feed"}
	other := Source{ID: "dropped", Name: "Dropped", URL: "https://example.com/other"}
	dir := t.TempDir()

	first := New(Config{DataDir: dir, Sources: []Source{source, other}})
	if err := first.Set(true, []string{"kept"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	second := New(Config{DataDir: dir, Sources: []Source{source, other}})
	if !second.Enabled() {
		t.Fatal("the enabled flag did not persist")
	}
	feed := second.Feed(context.Background())
	if len(feed.Sources) != 2 {
		t.Fatalf("sources = %+v", feed.Sources)
	}
	if !feed.Sources[0].Enabled || feed.Sources[1].Enabled {
		t.Fatalf("sources = %+v, want only the stored one enabled", feed.Sources)
	}

	if err := second.Set(false, nil); err != nil {
		t.Fatalf("Set(false): %v", err)
	}
	if New(Config{DataDir: dir, Sources: []Source{source}}).Enabled() {
		t.Fatal("the disabled flag did not persist")
	}
}

func TestSetRejectsAnUnknownSource(t *testing.T) {
	service := New(Config{DataDir: t.TempDir(), Sources: []Source{
		{ID: "known", Name: "Known", URL: "https://example.com/feed"},
	}})
	if err := service.Set(true, []string{"missing"}); err == nil {
		t.Fatal("Set accepted an unknown source")
	}
}

func TestDisabledSetClearsCache(t *testing.T) {
	var hits atomic.Int32
	server := testServer(t, rssFixture, nil, &hits)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, func() time.Time { return now })

	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	service.Feed(context.Background())

	if err := service.Set(false, nil); err != nil {
		t.Fatalf("Set(false): %v", err)
	}
	service.Feed(context.Background())
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (no fetch while off)", got)
	}

	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set(true): %v", err)
	}
	service.Feed(context.Background())
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 (cache was cleared on disable)", got)
	}
}

func TestFeedCapsTheResponseSize(t *testing.T) {
	// A feed larger than the cap is rejected instead of buffered without bound.
	large := strings.Repeat("x", maxFeedBytes+1)
	server := testServer(t, large, nil, nil)
	service := newTestService(t, []Source{
		{ID: "large", Name: "Large", URL: server.URL, Recommended: true},
	}, time.Now)
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	feed := service.Feed(context.Background())
	if len(feed.Items) != 0 {
		t.Fatalf("items = %d, want none from an oversized feed", len(feed.Items))
	}
	if feed.Sources[0].Error == "" {
		t.Fatal("the oversized feed did not report an error")
	}
}

func TestFailedFetchRetriesAfterShortBackoff(t *testing.T) {
	var hits atomic.Int32
	status := atomic.Int32{}
	status.Store(http.StatusInternalServerError)
	server := testServer(t, rssFixture, &status, &hits)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, func() time.Time { return now })
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	feed := service.Feed(context.Background())
	if feed.Sources[0].Error == "" {
		t.Fatal("the failed source did not report an error")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}

	// Inside the short error window the failure is not retried.
	now = now.Add(time.Minute)
	service.Feed(context.Background())
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 inside the error backoff", got)
	}

	// Past the error window it retries without waiting for the full TTL.
	now = now.Add(2 * time.Minute)
	status.Store(0)
	feed = service.Feed(context.Background())
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 after the error backoff", got)
	}
	if len(feed.Items) != 2 {
		t.Fatalf("items = %d, want the feed after recovery", len(feed.Items))
	}
}

func TestCanceledRequestStillFillsTheCache(t *testing.T) {
	var hits atomic.Int32
	server := testServer(t, rssFixture, nil, &hits)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, func() time.Time { return now })
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	feed := service.Feed(ctx)
	if len(feed.Items) != 2 {
		t.Fatalf("items = %d, want 2 despite the caller's canceled context", len(feed.Items))
	}

	// The cache is fresh, so a later call is served without another request.
	service.Feed(context.Background())
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (the cache was filled)", got)
	}
}

func TestExternalSettingsChangeIsPickedUp(t *testing.T) {
	var hits atomic.Int32
	server := testServer(t, rssFixture, nil, &hits)
	sources := []Source{{ID: "one", Name: "One", URL: server.URL, Recommended: true}}
	dir := t.TempDir()

	// This service is the long-lived MCP process: it started while off.
	mcp := New(Config{DataDir: dir, Sources: sources, Version: "test"})
	if mcp.Enabled() {
		t.Fatal("a fresh install must be off")
	}

	// Another process (the UI) stores the setting.
	ui := New(Config{DataDir: dir, Sources: sources, Version: "test"})
	if err := ui.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if !mcp.Enabled() {
		t.Fatal("the long-lived service did not reload the stored setting")
	}
	if feed := mcp.Feed(context.Background()); len(feed.Items) != 2 {
		t.Fatalf("items = %d, want the reloaded feed", len(feed.Items))
	}
}

func TestRedirectsStayOnTheFeedHost(t *testing.T) {
	feedServer := testServer(t, rssFixture, nil, nil)
	sameHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feed" {
			http.Redirect(w, r, "/real", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(rssFixture))
	}))
	t.Cleanup(sameHost.Close)

	service := newTestService(t, []Source{
		{ID: "same", Name: "Same", URL: sameHost.URL + "/feed", Recommended: true},
	}, time.Now)
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if feed := service.Feed(context.Background()); len(feed.Items) != 2 {
		t.Fatalf("same-host redirect items = %d, want 2", len(feed.Items))
	}

	otherHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, feedServer.URL, http.StatusFound)
	}))
	t.Cleanup(otherHost.Close)
	cross := newTestService(t, []Source{
		{ID: "cross", Name: "Cross", URL: otherHost.URL, Recommended: true},
	}, time.Now)
	if err := cross.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if feed := cross.Feed(context.Background()); feed.Sources[0].Error == "" || len(feed.Items) != 0 {
		t.Fatalf("cross-host redirect = %+v, want an isolated error", feed)
	}

	scheme := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	t.Cleanup(scheme.Close)
	unsupported := newTestService(t, []Source{
		{ID: "scheme", Name: "Scheme", URL: scheme.URL, Recommended: true},
	}, time.Now)
	if err := unsupported.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if feed := unsupported.Feed(context.Background()); feed.Sources[0].Error == "" {
		t.Fatalf("unsupported scheme redirect = %+v, want an error", feed)
	}
}

func TestFailedRefreshKeepsPreviousItems(t *testing.T) {
	var hits atomic.Int32
	var status atomic.Int32
	server := testServer(t, rssFixture, &status, &hits)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, []Source{
		{ID: "one", Name: "One", URL: server.URL, Recommended: true},
	}, func() time.Time { return now })
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	service.Feed(context.Background())

	status.Store(http.StatusInternalServerError)
	now = now.Add(DefaultTTL + time.Minute)
	feed := service.Feed(context.Background())
	if feed.Sources[0].Error == "" {
		t.Fatal("the failed refresh did not report an error")
	}
	if len(feed.Items) != 2 {
		t.Fatalf("items = %d, want the previous 2", len(feed.Items))
	}

	// The short retry window is measured from the failure.
	now = now.Add(time.Minute)
	service.Feed(context.Background())
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 inside the error backoff", got)
	}
}
