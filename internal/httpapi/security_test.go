package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHealthRequiresSessionCookie(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/api/health", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	problem := readProblem(t, resp)
	if problem.Status != http.StatusUnauthorized {
		t.Errorf("problem.status = %d, want %d", problem.Status, http.StatusUnauthorized)
	}
	if !strings.Contains(*problem.Detail, "bastion_session") {
		t.Errorf("problem.detail = %q, want it to name the cookie", *problem.Detail)
	}
}

func TestHealthWithSessionCookie(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/health", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("status = %q, want %q", health.Status, "ok")
	}
	if health.Version != "test-version" {
		t.Errorf("version = %q, want %q", health.Version, "test-version")
	}
}

func TestWrongCookieRejected(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/api/health", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-the-session"}) //nolint:gosec // G124: test request cookie
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	readProblem(t, resp)
}

// TestTokenExchange covers the cookie the exchange must set: HttpOnly,
// SameSite=Strict, Path=/, no Secure (the transport is http on loopback).
func TestTokenExchange(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/?t="+ts.token, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if got, want := resp.Header.Get("Location"), "/"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != SessionCookieName {
		t.Errorf("cookie name = %q, want %q", cookie.Name, SessionCookieName)
	}
	if !cookie.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("cookie Path = %q, want %q", cookie.Path, "/")
	}
	if cookie.Secure {
		t.Error("cookie is Secure, but the transport is uncompressed http on loopback")
	}
	if cookie.Value == ts.token {
		t.Error("cookie value equals the startup token; a leaked token could be replayed as a cookie")
	}

	// The cookie works for the API and the UI.
	if resp := ts.do(t, http.MethodGet, "/api/health", withCookie(cookie)); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/health with cookie: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp := ts.do(t, http.MethodGet, "/", withCookie(cookie)); resp.StatusCode != http.StatusOK {
		t.Errorf("GET / with cookie: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestTokenExchangeStripsTokenFromRedirect is the anti-history rule: the token
// must not survive into the address bar, while other parameters do.
func TestTokenExchangeStripsTokenFromRedirect(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/?t="+ts.token+"&tab=projects&q=a%20b", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}

	location := resp.Header.Get("Location")
	if strings.Contains(location, "t="+ts.token) || strings.Contains(location, ts.token) {
		t.Fatalf("Location %q still carries the token", location)
	}
	if strings.Contains(location, "tab=other") {
		t.Fatalf("Location %q dropped unrelated query parameters", location)
	}
	if !strings.Contains(location, "tab=projects") || !strings.Contains(location, "q=a+b") {
		t.Errorf("Location = %q, want it to keep tab=projects and q=a+b", location)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/?t="+ts.token, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second exchange: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("second exchange set a cookie")
	}
	readProblem(t, resp)

	// The cookie from the first exchange keeps working.
	if resp := ts.do(t, http.MethodGet, "/api/health", withCookie(cookie)); resp.StatusCode != http.StatusOK {
		t.Errorf("cookie after reuse attempt: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestUnknownTokenRejected(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/?t=not-the-token", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("unknown token set a cookie")
	}
	readProblem(t, resp)

	// The real token is still usable: guessing must not burn it.
	if resp := ts.do(t, http.MethodGet, "/?t="+ts.token, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("valid token after a failed guess: status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
}

// TestHostCheckRejectsDNSRebinding: a page on another origin that resolves its
// own domain to 127.0.0.1 still sends its own Host header.
func TestHostCheckRejectsDNSRebinding(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	// The cookie is valid, so only the Host check can reject these.
	for _, path := range []string{"/api/health", "/"} {
		resp := ts.do(t, http.MethodGet, path, func(r *http.Request) {
			r.Host = "evil.example.com"
			r.AddCookie(cookie)
		})
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("GET %s with foreign Host: status = %d, want %d", path, resp.StatusCode, http.StatusMisdirectedRequest)
		}
		readProblem(t, resp)
	}
}

// TestHostCheckAcceptsLocalhost: the printed URL uses 127.0.0.1, but a user may
// type localhost, and the browser then sends that Host.
func TestHostCheckAcceptsLocalhost(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/health", func(r *http.Request) {
		r.Host = strings.Replace(ts.url, "http://127.0.0.1", "localhost", 1)
		r.AddCookie(cookie)
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHostCheckRequiresTheServedPort: another port is another origin.
func TestHostCheckRequiresTheServedPort(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/health", func(r *http.Request) {
		r.Host = "127.0.0.1:1"
		r.AddCookie(cookie)
	})
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMisdirectedRequest)
	}
}

// TestCSRFHeaderRequiredOnMutations: a cross-site form can produce these
// methods without CORS, but it cannot set X-Bastion: 1.
func TestCSRFHeaderRequiredOnMutations(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	mutating := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, method := range mutating {
		resp := ts.do(t, method, "/api/unknown", withCookie(cookie))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s without X-Bastion: status = %d, want %d", method, resp.StatusCode, http.StatusForbidden)
		}
		readProblem(t, resp)

		resp = ts.do(t, method, "/api/unknown", func(r *http.Request) {
			r.AddCookie(cookie)
			r.Header.Set(csrfHeaderName, csrfHeaderVal)
		})
		if resp.StatusCode == http.StatusForbidden {
			t.Fatalf("%s with X-Bastion was rejected as CSRF", method)
		}
	}
}

func TestCSRFHeaderNotRequiredForReads(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/health", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestNoCORSHeaders: bastion has no cross-origin clients, so no response may
// advertise CORS, including an OPTIONS preflight.
func TestNoCORSHeaders(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	cases := []struct {
		name   string
		method string
		path   string
		mutate func(*http.Request)
	}{
		{name: "options preflight", method: http.MethodOptions, path: "/api/health", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example.com")
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			r.Header.Set("Access-Control-Request-Headers", "x-bastion")
		}},
		{name: "simple request with origin", method: http.MethodGet, path: "/api/health", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example.com")
			r.AddCookie(cookie)
		}},
		{name: "ui", method: http.MethodGet, path: "/", mutate: withCookie(cookie)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, tc.method, tc.path, tc.mutate)
			for header := range resp.Header {
				if strings.HasPrefix(strings.ToLower(header), "access-control-") {
					t.Errorf("response carries %s: %q", header, resp.Header.Get(header))
				}
			}
		})
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	cases := []struct {
		name   string
		method string
		path   string
		mutate func(*http.Request)
	}{
		{name: "authorized api", method: http.MethodGet, path: "/api/health", mutate: withCookie(cookie)},
		{name: "unauthorized api", method: http.MethodGet, path: "/api/health"},
		{name: "bad host", method: http.MethodGet, path: "/api/health", mutate: func(r *http.Request) { r.Host = "evil.example.com" }},
		{name: "ui", method: http.MethodGet, path: "/", mutate: withCookie(cookie)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, tc.method, tc.path, tc.mutate)
			want := map[string]string{
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "no-referrer",
				"X-Frame-Options":        "DENY",
			}
			for header, value := range want {
				if got := resp.Header.Get(header); got != value {
					t.Errorf("%s = %q, want %q", header, got, value)
				}
			}
		})
	}
}

func TestUIServesPlaceholderWithCSP(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Content-Security-Policy"), "default-src 'self'"; got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "bastion is running") {
		t.Errorf("body does not contain the placeholder text: %q", body)
	}
}

func TestUIRefusesUnauthenticated(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	readProblem(t, resp)
}

// TestTokenNeverLogged is the redaction rule of §4.3: the token arrives in the
// query string, which the request log must not contain.
func TestTokenNeverLogged(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	_ = ts.do(t, http.MethodGet, "/api/health", withCookie(cookie))

	logs := ts.logs.String()
	if logs == "" {
		t.Fatal("no request logs were written")
	}
	for _, secret := range []string{ts.token, ts.session} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log output contains a credential: %q", logs)
		}
	}
	if strings.Contains(logs, "t=") {
		t.Errorf("log output contains a query string: %q", logs)
	}

	// The log is still useful: method, path, status and duration.
	lines := ts.logs.logLines(t)
	var found bool
	for _, line := range lines {
		if line["path"] != "/api/health" {
			continue
		}
		found = true
		if line["method"] != http.MethodGet {
			t.Errorf("method = %v, want GET", line["method"])
		}
		if status, ok := line["status"].(float64); !ok || int(status) != http.StatusOK {
			t.Errorf("status = %v, want 200", line["status"])
		}
		if _, ok := line["duration_ms"]; !ok {
			t.Error("log line has no duration_ms")
		}
	}
	if !found {
		t.Fatalf("no log line for /api/health in %q", logs)
	}
}

// TestAPIErrorsAreProblemJSON covers the error shape for API failures other
// than authentication.
func TestAPIErrorsAreProblemJSON(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/nope", withCookie(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	problem := readProblem(t, resp)
	if problem.Title != "Not Found" {
		t.Errorf("problem.title = %q, want %q", problem.Title, "Not Found")
	}
}

// TestListenBindsLoopbackOnly guards the first rule of §4.3.
func TestListenBindsLoopbackOnly(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("address %q is not TCP", ln.Addr())
	}
	if !addr.IP.IsLoopback() || addr.IP.String() != "127.0.0.1" {
		t.Errorf("listener bound to %q, want 127.0.0.1", addr.IP)
	}
	if addr.Port == 0 {
		t.Error("listener did not bind an ephemeral port")
	}
}

// TestListenHonoursRequestedPort keeps `--port` honest.
func TestListenHonoursRequestedPort(t *testing.T) {
	first, err := Listen(0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := first.Addr().(*net.TCPAddr).Port
	_ = first.Close()

	second, err := Listen(port)
	if err != nil {
		t.Fatalf("Listen(%d): %v", port, err)
	}
	defer func() { _ = second.Close() }()

	if got := second.Addr().(*net.TCPAddr).Port; got != port {
		t.Errorf("bound port = %d, want %d", got, port)
	}
}

// TestServeShutsDownGracefully checks that cancellation stops the listener
// instead of leaving the process hanging.
func TestServeShutsDownGracefully(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv, err := New(Config{Version: "test", Port: port})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	waitForServer(t, http.DefaultClient, srv.BaseURL())
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}

	if _, err := net.DialTimeout("tcp", srv.BaseURL()[len("http://"):], 200*time.Millisecond); err == nil {
		t.Error("listener still accepts connections after shutdown")
	}
}
