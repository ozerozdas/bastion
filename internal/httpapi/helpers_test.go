package httpapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// testServer is a Server listening on a real loopback port, with request logs
// captured so tests can assert what was (and was not) written.
type testServer struct {
	*Server

	url    string
	logs   *syncBuffer
	client *http.Client
}

// newTestServer starts the server on an ephemeral loopback port. Tests use
// httptest with a pre-bound listener so the port in the URL is the port the
// server validates the Host header against.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port, err := listenerPort(t, ln)
	if err != nil {
		t.Fatalf("listener port: %v", err)
	}

	logs := &syncBuffer{}
	srv, err := New(Config{
		Version: "test-version",
		Port:    port,
		Logger:  slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewUnstartedServer(srv.Handler())
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)

	return &testServer{
		Server: srv,
		url:    ts.URL, // http://127.0.0.1:<port>
		logs:   logs,
		client: &http.Client{
			// Redirects are asserted, not followed.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 5 * time.Second,
		},
	}
}

// listenerPort returns the port a test listener bound to.
func listenerPort(t *testing.T, ln net.Listener) (int, error) {
	t.Helper()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %q is not TCP", ln.Addr())
	}
	return addr.Port, nil
}

// do sends a request to the test server and returns the response. body may be
// nil. The caller closes the body.
func (ts *testServer) do(t *testing.T, method, path string, mutate func(*http.Request)) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, ts.url+path, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// login performs the token exchange and returns the session cookie.
func (ts *testServer) login(t *testing.T) *http.Cookie {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/?t="+ts.token, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("token exchange: status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("token exchange: got %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

// withCookie attaches the session cookie to a request.
func withCookie(cookie *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(cookie) }
}

// readProblem decodes an RFC 9457 problem+json body.
func readProblem(t *testing.T, resp *http.Response) gen.Problem {
	t.Helper()

	if got, want := resp.Header.Get("Content-Type"), "application/problem+json"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var problem gen.Problem
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("decode problem %q: %v", body, err)
	}
	return problem
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logLines returns the captured log lines, decoded from JSON.
func (b *syncBuffer) logLines(t *testing.T) []map[string]any {
	t.Helper()

	var lines []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(b.String()))
	for scanner.Scan() {
		var line map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("log line %q is not JSON: %v", scanner.Text(), err)
		}
		lines = append(lines, line)
	}
	return lines
}

// waitForServer blocks until the server answers, so tests do not race the
// listener goroutine.
func waitForServer(t *testing.T, client *http.Client, url string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url + "/api/health")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not come up", url)
}
