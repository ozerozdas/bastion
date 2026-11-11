package httpapi

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ozerozdas/bastion/web"
)

// testUIFS is a stand-in build: one entry point and one hashed bundle.
func testUIFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte(`<!doctype html><html><body><div id="root"></div></body></html>`),
		},
		"assets/index-abc123.js": &fstest.MapFile{Data: []byte("console.log('ui')")},
		"assets/index-def456.css": &fstest.MapFile{
			Data: []byte(":root{color-scheme:light dark}"),
		},
	}
}

func TestUIHandlerRouting(t *testing.T) {
	ui := newUIHandler(testUIFS(), slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantType   string
		wantBody   string
		wantNoCSP  bool
	}{
		{
			name:       "root serves the entry point",
			method:     http.MethodGet,
			path:       "/",
			wantStatus: http.StatusOK,
			wantType:   "text/html; charset=utf-8",
			wantBody:   `<div id="root">`,
		},
		{
			name:       "client route falls back to the entry point",
			method:     http.MethodGet,
			path:       "/projects",
			wantStatus: http.StatusOK,
			wantType:   "text/html; charset=utf-8",
			wantBody:   `<div id="root">`,
		},
		{
			name:       "nested client route falls back too",
			method:     http.MethodGet,
			path:       "/security-reports/42",
			wantStatus: http.StatusOK,
			wantType:   "text/html; charset=utf-8",
			wantBody:   `<div id="root">`,
		},
		{
			name:       "hashed asset is served as javascript",
			method:     http.MethodGet,
			path:       "/assets/index-abc123.js",
			wantStatus: http.StatusOK,
			wantType:   "text/javascript; charset=utf-8",
			wantBody:   "console.log",
			wantNoCSP:  true,
		},
		{
			name:       "stylesheet is served as css",
			method:     http.MethodGet,
			path:       "/assets/index-def456.css",
			wantStatus: http.StatusOK,
			wantType:   "text/css; charset=utf-8",
			wantBody:   "color-scheme",
			wantNoCSP:  true,
		},
		{
			name:       "missing asset is a problem, not the SPA",
			method:     http.MethodGet,
			path:       "/assets/missing.js",
			wantStatus: http.StatusNotFound,
			wantType:   "application/problem+json",
			wantNoCSP:  true,
		},
		{
			name:       "missing file-like path is not the SPA",
			method:     http.MethodGet,
			path:       "/favicon.svg",
			wantStatus: http.StatusNotFound,
			wantType:   "application/problem+json",
			wantNoCSP:  true,
		},
		{
			name:       "mutating methods are refused",
			method:     http.MethodPost,
			path:       "/",
			wantStatus: http.StatusMethodNotAllowed,
			wantType:   "application/problem+json",
			wantNoCSP:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ui.ServeHTTP(rec, httptest.NewRequest(test.method, test.path, http.NoBody))

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, test.wantStatus)
			}
			if got := rec.Header().Get("Content-Type"); got != test.wantType {
				t.Errorf("Content-Type = %q, want %q", got, test.wantType)
			}
			if test.wantBody != "" && !strings.Contains(rec.Body.String(), test.wantBody) {
				t.Errorf("body does not contain %q: %q", test.wantBody, rec.Body.String())
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if test.wantNoCSP && csp != "" {
				t.Errorf("Content-Security-Policy = %q, want none", csp)
			}
			if !test.wantNoCSP && csp != "default-src 'self'" {
				t.Errorf("Content-Security-Policy = %q, want %q", csp, "default-src 'self'")
			}
		})
	}
}

// TestUIHandlerWithoutBuildServesPlaceholder covers a fresh clone or a bare
// `go build`, where web/dist holds only its .gitkeep.
func TestUIHandlerWithoutBuildServesPlaceholder(t *testing.T) {
	ui := newUIHandler(fstest.MapFS{".gitkeep": &fstest.MapFile{}}, slog.New(slog.DiscardHandler))

	rec := httptest.NewRecorder()
	ui.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/projects", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "bastion is running") {
		t.Errorf("body does not contain the placeholder text: %q", rec.Body.String())
	}
}

// TestUIHandlerIgnoresPathTraversal makes sure a crafted path cannot read
// outside the embedded tree.
func TestUIHandlerIgnoresPathTraversal(t *testing.T) {
	ui := newUIHandler(testUIFS(), slog.New(slog.DiscardHandler))

	rec := httptest.NewRecorder()
	ui.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/../../etc/passwd", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the SPA fallback (%d)", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `<div id="root">`) {
		t.Errorf("body is not the entry point: %q", rec.Body.String())
	}
}

// TestSPARouteBehindSession runs the fallback through the whole middleware
// stack: no cookie means 401, a cookie means the SPA, never a 404.
func TestSPARouteBehindSession(t *testing.T) {
	ts := newTestServer(t)

	unauthenticated := ts.do(t, http.MethodGet, "/projects", nil)
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without cookie = %d, want %d", unauthenticated.StatusCode, http.StatusUnauthorized)
	}
	readProblem(t, unauthenticated)

	cookie := ts.login(t)
	resp := ts.do(t, http.MethodGet, "/projects", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Content-Security-Policy"), "default-src 'self'"; got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}
}

// TestBuiltAssetServedFromEmbed fetches a real file of the built bundle. It is
// skipped when `npm run build` has not produced one (make check builds first).
func TestBuiltAssetServedFromEmbed(t *testing.T) {
	dist := web.Dist()
	entries, err := fs.ReadDir(dist, "assets")
	if err != nil {
		t.Skip("web/dist/assets is absent: run `npm --prefix web run build`")
	}

	var asset string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".js") {
			asset = entry.Name()
			break
		}
	}
	if asset == "" {
		t.Skip("web/dist/assets has no javascript bundle")
	}

	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, path.Join("/assets", asset), withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/javascript; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("Cache-Control = %q, want it to allow immutable caching", got)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read asset: %v", err)
	}
}
