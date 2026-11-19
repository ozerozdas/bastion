package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/securitynews"
)

const securityNewsFixture = `<?xml version="1.0"?>
<rss version="2.0"><channel><title>Feed</title>
<item><title>Advisory</title><link>https://example.com/a</link><pubDate>Sun, 15 Nov 2026 12:00:00 GMT</pubDate><description><![CDATA[<b>Patch</b> now.]]></description></item>
</channel></rss>`

// securityNewsTestService serves a fixture feed and counts requests.
func securityNewsTestService(t *testing.T, hits *atomic.Int32) *securitynews.Service {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(securityNewsFixture))
	}))
	t.Cleanup(server.Close)

	return securitynews.New(securitynews.Config{
		DataDir: t.TempDir(),
		Sources: []securitynews.Source{
			{ID: "example", Name: "Example Feed", URL: server.URL, Recommended: true},
		},
		Version: "test",
	})
}

func readSecurityNews(t *testing.T, resp *http.Response) gen.SecurityNewsFeed {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var feed gen.SecurityNewsFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		t.Fatalf("decode Security News feed: %v", err)
	}
	return feed
}

func TestSecurityNewsOffMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithSecurityNews(t, securityNewsTestService(t, &hits))
	cookie := ts.login(t)

	feed := readSecurityNews(t, ts.do(t, http.MethodGet, "/api/security-news", withCookie(cookie)))
	if feed.Enabled {
		t.Error("enabled = true on a fresh install")
	}
	if len(feed.Items) != 0 {
		t.Errorf("items = %d, want none while off", len(feed.Items))
	}
	if len(feed.Sources) != 1 || !feed.Sources[0].Recommended {
		t.Errorf("sources = %+v, want the recommended preset", feed.Sources)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("feed requests = %d, want 0 with Security News off", got)
	}
}

func TestSetSecurityNewsStoresAndServes(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithSecurityNews(t, securityNewsTestService(t, &hits))
	cookie := ts.login(t)

	// Storing the choice does not fetch; the next read does.
	stored := readSecurityNews(t, ts.doJSON(t, http.MethodPut, "/api/security-news",
		`{"enabled":true,"sources":["example"]}`, cookie, true))
	if !stored.Enabled {
		t.Error("enabled = false after opting in")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("feed requests = %d, want 0 on the PUT", got)
	}

	feed := readSecurityNews(t, ts.do(t, http.MethodGet, "/api/security-news", withCookie(cookie)))
	if len(feed.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(feed.Items))
	}
	item := feed.Items[0]
	if item.Title != "Advisory" || item.Summary != "Patch now." {
		t.Errorf("item = %+v, want sanitized text", item)
	}
	if item.Link != "https://example.com/a" {
		t.Errorf("link = %q", item.Link)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("feed requests = %d, want 1", got)
	}

	off := readSecurityNews(t, ts.doJSON(t, http.MethodPut, "/api/security-news",
		`{"enabled":false}`, cookie, true))
	if off.Enabled {
		t.Error("enabled = true after opting out")
	}
}

func TestSetSecurityNewsRejectsUnknownSource(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithSecurityNews(t, securityNewsTestService(t, &hits))
	cookie := ts.login(t)

	resp := ts.doJSON(t, http.MethodPut, "/api/security-news",
		`{"enabled":true,"sources":["missing"]}`, cookie, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("feed requests = %d, want 0", got)
	}
}

func TestSecurityNewsNeedsASession(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithSecurityNews(t, securityNewsTestService(t, &hits))

	resp := ts.do(t, http.MethodGet, "/api/security-news", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("feed requests = %d, want 0", got)
	}
}
