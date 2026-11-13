package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/events"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/update"
)

// fakeGitHub stands in for internal/connections/github. Handler tests never
// call GitHub: they drive User and ListRepos through this fake.
type fakeGitHub struct {
	mu       sync.Mutex
	user     github.User
	userErr  error
	repos    []github.Repo
	reposErr error
	repo     github.Repo
	repoErr  error
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{user: github.User{Login: "octocat"}}
}

func (f *fakeGitHub) User(context.Context) (github.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.user, f.userErr
}

func (f *fakeGitHub) ListRepos(context.Context) ([]github.Repo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.repos, f.reposErr
}

// Repo answers asset creation's default-branch lookup. The zero repo resolves
// to owner/name on main, so tests only set repo when they need another answer.
func (f *fakeGitHub) Repo(_ context.Context, owner, name string) (github.Repo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repoErr != nil {
		return github.Repo{}, f.repoErr
	}
	if f.repo.FullName == "" {
		return github.Repo{FullName: owner + "/" + name, DefaultBranch: "main"}, nil
	}
	return f.repo, nil
}

func (f *fakeGitHub) setUserErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userErr = err
}

func (f *fakeGitHub) setRepos(repos []github.Repo, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos, f.reposErr = repos, err
}

// fakeTokens answers every credential lookup, so asset creation never needs a
// keyring or the environment fallback.
type fakeTokens struct{}

func (fakeTokens) Token(context.Context) (string, error) { return "test-token", nil }

func (fakeTokens) ConnectionToken(context.Context, int64) (string, error) {
	return "test-token", nil
}

// testServer is a Server listening on a real loopback port, with request logs
// captured so tests can assert what was (and was not) written.
type testServer struct {
	*Server

	url         string
	logs        *syncBuffer
	client      *http.Client
	db          *sql.DB
	secretStore *secrets.MemoryStore
	github      *fakeGitHub
	scanManager *jobs.Manager
	events      *events.Broker
}

// newTestServer starts the server on an ephemeral loopback port. Tests use
// httptest with a pre-bound listener so the port in the URL is the port the
// server validates the Host header against.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	return newTestServerWithGitHub(t, nil)
}

// newTestServerWithGitHub is newTestServer with a caller-controlled fake
// GitHub. A nil fake gets one whose User succeeds as "octocat".
func newTestServerWithGitHub(t *testing.T, fake *fakeGitHub) *testServer {
	t.Helper()
	return newTestServerWithUpdate(t, fake, nil)
}

// newTestServerWithUpdate is newTestServerWithGitHub with a caller-controlled
// release checker. A nil checker gets unset consent and throwaway directories,
// so no test accidentally reads or writes the user's data.
func newTestServerWithUpdate(t *testing.T, fake *fakeGitHub, checker *update.Checker) *testServer {
	t.Helper()
	return newTestServerWithConfig(t, fake, checker, nil)
}

// newTestServerWithTrivyDB is newTestServer with a caller-controlled
// vulnerability DB manager, so handler tests observe real manager states
// without ever reaching the network.
func newTestServerWithTrivyDB(t *testing.T, manager *trivy.Manager) *testServer {
	t.Helper()
	return newTestServerWithConfig(t, nil, nil, manager)
}

// newTestServerWithConfig builds the test server with every optional service a
// caller wants to control. Nil values get the defaults described above.
func newTestServerWithConfig(t *testing.T, fake *fakeGitHub, checker *update.Checker, manager *trivy.Manager) *testServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port, err := listenerPort(t, ln)
	if err != nil {
		t.Fatalf("listener port: %v", err)
	}

	if fake == nil {
		fake = newFakeGitHub()
	}
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	secretStore := secrets.NewMemoryStore()
	service, err := connections.NewService(db, secretStore, connections.WithGitHubFactory(
		func(string) (connections.GitHubClient, error) { return fake, nil },
	))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	reportService, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	// No sources or scanners: a queued scan fails its pipeline quickly, which
	// is all the API tests need (the endpoint contract, not scanning).
	bus := events.NewBroker()
	scanManager, err := jobs.New(jobs.Config{DB: db, Concurrency: 1, Events: bus})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	t.Cleanup(func() { _ = scanManager.Close() })

	assetService, err := assets.NewService(db,
		assets.WithScanManager(scanManager),
		assets.WithGitHub(
			func(string) (assets.RepoClient, error) { return fake, nil },
			fakeTokens{},
		),
	)
	if err != nil {
		t.Fatalf("assets.NewService: %v", err)
	}

	logs := &syncBuffer{}
	if checker == nil {
		checker = update.New(update.Config{
			CurrentVersion: "test-version",
			DataDir:        t.TempDir(),
			CacheDir:       t.TempDir(),
			Getenv:         func(string) string { return "" },
		})
	}
	srv, err := New(Config{
		Version:     "test-version",
		Port:        port,
		Logger:      slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Connections: service,
		Reports:     reportService,
		Assets:      assetService,
		Events:      bus,
		Update:      checker,
		TrivyDB:     manager,
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
		Server:      srv,
		url:         ts.URL, // http://127.0.0.1:<port>
		logs:        logs,
		db:          db,
		secretStore: secretStore,
		github:      fake,
		scanManager: scanManager,
		events:      bus,
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("token exchange: got %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

// refreshTarget returns the URL the token-exchange page refreshes to.
func refreshTarget(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read exchange page: %v", err)
	}
	_, rest, ok := strings.Cut(string(body), `content="0; url=`)
	if !ok {
		t.Fatalf("exchange page has no refresh: %s", body)
	}
	target, _, _ := strings.Cut(rest, `"`)
	return html.UnescapeString(target)
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
