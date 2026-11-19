package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/securitynews"
)

const securityNewsFixture = `<?xml version="1.0"?>
<rss version="2.0"><channel><title>Feed</title>
<item><title>Newer advisory</title><link>https://example.com/a</link><pubDate>Sun, 15 Nov 2026 12:00:00 GMT</pubDate><description><![CDATA[<b>Patch</b> now.]]></description></item>
<item><title>Older advisory</title><link>https://example.com/b</link><pubDate>Sat, 14 Nov 2026 12:00:00 GMT</pubDate><description>Older.</description></item>
</channel></rss>`

func TestListSecurityNewsIsDisabledByDefault(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(securityNewsFixture))
	}))
	t.Cleanup(server.Close)

	service := securitynews.New(securitynews.Config{
		DataDir: t.TempDir(),
		Sources: []securitynews.Source{{ID: "feed", Name: "Feed", URL: server.URL, Recommended: true}},
	})
	db := openTestDB(t)
	session := newSession(t, mcpserver.Config{
		Assets:       newAssetsService(t, db),
		Reports:      newReportsService(t, db),
		SecurityNews: service,
	})

	message := callError(t, session, "list_security_news", nil)
	if !strings.Contains(message, "disabled") {
		t.Fatalf("error = %q, want a disabled-feature message", message)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 while disabled", got)
	}
}

func TestListSecurityNewsReadsTheFeed(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(securityNewsFixture))
	}))
	t.Cleanup(server.Close)

	service := securitynews.New(securitynews.Config{
		DataDir: t.TempDir(),
		Sources: []securitynews.Source{{ID: "feed", Name: "Feed", URL: server.URL, Recommended: true}},
	})
	if err := service.Set(true, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	db := openTestDB(t)
	session := newSession(t, mcpserver.Config{
		Assets:       newAssetsService(t, db),
		Reports:      newReportsService(t, db),
		SecurityNews: service,
	})

	type item struct {
		Title     string `json:"title"`
		SourceID  string `json:"source_id"`
		Published string `json:"published"`
		Link      string `json:"link"`
		Summary   string `json:"summary"`
	}
	type data struct {
		Items   []item   `json:"items"`
		Count   int      `json:"count"`
		Sources []string `json:"sources"`
	}
	out := call[envelope[data]](t, session, "list_security_news", nil)
	if out.UntrustedContent != mcpserver.SecurityNewsNotice {
		t.Errorf("notice = %q", out.UntrustedContent)
	}
	if out.Data.Count != 2 || len(out.Data.Items) != 2 {
		t.Fatalf("data = %+v, want two items", out.Data)
	}
	if out.Data.Items[0].Title != "Newer advisory" {
		t.Errorf("first title = %q", out.Data.Items[0].Title)
	}
	if out.Data.Items[0].Summary != "Patch now." {
		t.Errorf("summary = %q", out.Data.Items[0].Summary)
	}
	if out.Data.Items[0].SourceID != "feed" {
		t.Errorf("source id = %q", out.Data.Items[0].SourceID)
	}
	if len(out.Data.Sources) != 1 || out.Data.Sources[0] != "feed" {
		t.Errorf("sources = %+v", out.Data.Sources)
	}

	// The limit caps the result.
	limited := call[envelope[data]](t, session, "list_security_news", map[string]any{"limit": 1})
	if limited.Data.Count != 1 {
		t.Fatalf("limited count = %d, want 1", limited.Data.Count)
	}

	// Since keeps only newer items; the network is not hit twice inside the TTL.
	since := call[envelope[data]](t, session, "list_security_news",
		map[string]any{"since": "2026-11-15T00:00:00Z"})
	if since.Data.Count != 1 || since.Data.Items[0].Title != "Newer advisory" {
		t.Fatalf("since data = %+v", since.Data)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (service cache shared)", got)
	}

	// A source the feed does not have yields no items.
	unknown := call[envelope[data]](t, session, "list_security_news",
		map[string]any{"source": "nope"})
	if unknown.Data.Count != 0 {
		t.Fatalf("unknown source count = %d, want 0", unknown.Data.Count)
	}

	// A bad since is a clear tool error, not a silent empty result.
	message := callError(t, session, "list_security_news", map[string]any{"since": "yesterday"})
	if !strings.Contains(message, "RFC 3339") {
		t.Fatalf("error = %q, want an RFC 3339 message", message)
	}
}
