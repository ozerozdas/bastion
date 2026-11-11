package github

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	// testToken is a fake credential every test asserts never leaks.
	testToken = "ghp_tokenThatMustNeverLeak1234567890" //nolint:gosec // fake credential; tests assert it never leaks.
	testSHA   = "0123456789abcdef0123456789abcdef01234567"
)

// newTestClient builds a client against srv. tweak may adjust the config; the
// token and base URL are filled in first.
func newTestClient(t *testing.T, srvURL string, tweak func(*Config)) *Client {
	t.Helper()

	cfg := Config{Token: testToken, BaseURL: srvURL, Version: "test"}
	if tweak != nil {
		tweak(&cfg)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "no token", cfg: Config{}},
		{name: "bad scheme", cfg: Config{Token: "t", BaseURL: "ftp://api.github.com"}},
		{name: "no host", cfg: Config{Token: "t", BaseURL: "https://"}},
		{name: "query in base", cfg: Config{Token: "t", BaseURL: "https://api.github.com?x=1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("New accepted an invalid config")
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	client, err := New(Config{Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := client.base.String(); got != DefaultBaseURL {
		t.Fatalf("base URL = %q, want %q", got, DefaultBaseURL)
	}
	if client.userAgent != "bastion/dev" {
		t.Fatalf("User-Agent = %q, want bastion/dev", client.userAgent)
	}
	if client.maxTarball != DefaultMaxTarballBytes {
		t.Fatalf("tarball cap = %d, want %d", client.maxTarball, DefaultMaxTarballBytes)
	}
}

func TestUserHeadersAndDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path = %q, want /user", r.URL.Path)
		}
		want := map[string]string{
			"Authorization":        "Bearer " + testToken,
			"Accept":               acceptJSON,
			"X-GitHub-Api-Version": apiVersion,
			"User-Agent":           "bastion/test",
		}
		for header, value := range want {
			if got := r.Header.Get(header); got != value {
				t.Errorf("%s = %q, want %q", header, got, value)
			}
		}
		_, _ = w.Write([]byte(`{"login":"acme-bot","name":"Acme Bot","id":42}`))
	}))
	t.Cleanup(srv.Close)

	user, err := newTestClient(t, srv.URL, nil).User(t.Context())
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if user.Login != "acme-bot" || user.Name != "Acme Bot" || user.ID != 42 {
		t.Fatalf("User = %+v", user)
	}
}

func TestListReposFollowsLinkPagination(t *testing.T) {
	pages := map[string]string{
		"":  `[{"full_name":"acme/one","owner":{"login":"acme"}},{"full_name":"acme/two"}]`,
		"2": `[{"full_name":"acme/three"}]`,
		"3": `[{"full_name":"acme/four"}]`,
	}
	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/user/repos" {
			t.Errorf("path = %q, want /user/repos", r.URL.Path)
		}
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q, want 100", got)
		}
		if got := r.URL.Query().Get("sort"); got != "pushed" {
			t.Errorf("sort = %q, want pushed", got)
		}

		page := r.URL.Query().Get("page")
		next := ""
		switch page {
		case "":
			next = "2"
		case "2":
			next = "3"
		}
		if next != "" {
			w.Header().Set("Link", `<http://`+r.Host+`/user/repos?per_page=100&sort=pushed&page=`+next+`>; rel="next", `+
				`<http://`+r.Host+`/user/repos?per_page=100&sort=pushed&page=3>; rel="last"`)
		}
		_, _ = w.Write([]byte(pages[page]))
	}))
	t.Cleanup(srv.Close)

	repos, err := newTestClient(t, srv.URL, nil).ListRepos(t.Context())
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	got := make([]string, 0, len(repos))
	for _, repo := range repos {
		got = append(got, repo.FullName)
	}
	want := []string{"acme/one", "acme/two", "acme/three", "acme/four"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3", got)
	}
}

func TestListReposPageLimit(t *testing.T) {
	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// Every response claims another page: the cap must stop the loop.
		w.Header().Set("Link", `<http://`+r.Host+`/user/repos?page=next>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	_, err := newTestClient(t, srv.URL, nil).ListRepos(t.Context())
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("ListRepos error = %v, want *Error", err)
	}
	if !strings.Contains(apiErr.Hint, "50 pages") {
		t.Fatalf("hint = %q, want the page limit", apiErr.Hint)
	}
	if got := requests.Load(); got != maxRepoPages {
		t.Fatalf("requests = %d, want %d", got, maxRepoPages)
	}
}

func TestListReposRejectsForeignNextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<http://evil.example/user/repos?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	_, err := newTestClient(t, srv.URL, nil).ListRepos(t.Context())
	if err == nil {
		t.Fatal("ListRepos followed a pagination link to another host")
	}
	if !strings.Contains(err.Error(), "another host") {
		t.Fatalf("error = %v, want a foreign-host hint", err)
	}
}

func TestErrorHints(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		headers  map[string]string
		wantHint string
		wantCode int
	}{
		{
			name:     "unauthorized",
			status:   http.StatusUnauthorized,
			wantHint: "token invalid or expired",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "rate limited",
			status:   http.StatusForbidden,
			headers:  map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000000"},
			wantHint: "rate limited until 2023-11-14T22:13:20Z",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "forbidden without rate limit",
			status:   http.StatusForbidden,
			wantHint: "",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "not found",
			status:   http.StatusNotFound,
			wantHint: "repo not found or token lacks access",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "server error",
			status:   http.StatusInternalServerError,
			wantHint: "",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for header, value := range tt.headers {
					w.Header().Set(header, value)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"message":"token ` + testToken + ` in body"}`))
			}))
			t.Cleanup(srv.Close)

			_, err := newTestClient(t, srv.URL, nil).Repo(t.Context(), "acme", "widgets")
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want *Error", err)
			}
			if apiErr.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d", apiErr.StatusCode, tt.wantCode)
			}
			if apiErr.Hint != tt.wantHint {
				t.Fatalf("hint = %q, want %q", apiErr.Hint, tt.wantHint)
			}
			if apiErr.Op != "get repo acme/widgets" {
				t.Fatalf("op = %q, want get repo acme/widgets", apiErr.Op)
			}
			if msg := err.Error(); strings.Contains(msg, testToken) {
				t.Fatalf("error carries the token: %s", msg)
			}
		})
	}
}

func TestRepoDecodesFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widgets" {
			t.Errorf("path = %q, want /repos/acme/widgets", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"full_name":"acme/widgets","name":"widgets","owner":{"login":"acme"},
			"default_branch":"trunk","private":true,"archived":false
		}`))
	}))
	t.Cleanup(srv.Close)

	repo, err := newTestClient(t, srv.URL, nil).Repo(t.Context(), "acme", "widgets")
	if err != nil {
		t.Fatalf("Repo: %v", err)
	}
	if repo.FullName != "acme/widgets" || repo.Owner.Login != "acme" {
		t.Fatalf("repo = %+v", repo)
	}
	if repo.DefaultBranch != "trunk" || !repo.Private || repo.Archived {
		t.Fatalf("repo = %+v", repo)
	}
}

func TestResolveSHA(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		body     string
		wantPath string
		wantSHA  string
		wantErr  bool
	}{
		{
			name:     "branch",
			ref:      "main",
			body:     testSHA + "\n",
			wantPath: "/repos/acme/widgets/commits/main",
			wantSHA:  testSHA,
		},
		{
			name:     "branch with a slash",
			ref:      "release/2.x",
			body:     testSHA,
			wantPath: "/repos/acme/widgets/commits/release/2.x",
			wantSHA:  testSHA,
		},
		{
			name:     "upper case is normalised",
			ref:      "main",
			body:     strings.ToUpper(testSHA),
			wantPath: "/repos/acme/widgets/commits/main",
			wantSHA:  testSHA,
		},
		{
			name:    "not a sha",
			ref:     "main",
			body:    `{"message":"Not Found"}`,
			wantErr: true,
		},
		{
			name:    "too short",
			ref:     "main",
			body:    "abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Accept"); got != acceptSHA {
					t.Errorf("Accept = %q, want %q", got, acceptSHA)
				}
				if tt.wantPath != "" && r.URL.Path != tt.wantPath {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.wantPath)
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(srv.Close)

			sha, err := newTestClient(t, srv.URL, nil).ResolveSHA(t.Context(), "acme", "widgets", tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveSHA = %q, want an error", sha)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSHA: %v", err)
			}
			if sha != tt.wantSHA {
				t.Fatalf("sha = %q, want %q", sha, tt.wantSHA)
			}
		})
	}
}

func TestValidatePathSegments(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	client := newTestClient(t, srv.URL, nil)

	invalid := []struct {
		name  string
		owner string
		repo  string
	}{
		{name: "empty owner", repo: "widgets"},
		{name: "owner with slash", owner: "acme/evil", repo: "widgets"},
		{name: "owner traversal", owner: "..", repo: "widgets"},
		{name: "empty repo", owner: "acme"},
		{name: "repo traversal", owner: "acme", repo: ".."},
		{name: "repo with query", owner: "acme", repo: "wid?gets"},
		{name: "repo with fragment", owner: "acme", repo: "wid#gets"},
		{name: "repo with newline", owner: "acme", repo: "wid\ngets"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.Repo(t.Context(), tt.owner, tt.repo); err == nil {
				t.Fatal("Repo accepted an invalid path segment")
			}
			if _, err := client.Tarball(t.Context(), tt.owner, tt.repo, testSHA); err == nil {
				t.Fatal("Tarball accepted an invalid path segment")
			}
		})
	}

	invalidRefs := []string{"", "..", "../user", "a//b", "a/./b", "main?x=1", "main\n"}
	for _, ref := range invalidRefs {
		t.Run("ref "+ref, func(t *testing.T) {
			if _, err := client.ResolveSHA(t.Context(), "acme", "widgets", ref); err == nil {
				t.Fatal("ResolveSHA accepted an invalid ref")
			}
		})
	}

	if _, err := client.Tarball(t.Context(), "acme", "widgets", "not-a-sha"); err == nil {
		t.Fatal("Tarball accepted a non-SHA ref")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid identifiers reached the server %d times", got)
	}
}

func TestTarballRedirectDropsAuthorization(t *testing.T) {
	var redirectedAuth atomic.Value
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("tarball-bytes"))
	}))
	t.Cleanup(second.Close)
	// The redirect must change host, not just port, for net/http to drop the
	// credential: localhost resolves to the same loopback listener.
	redirectURL := strings.Replace(second.URL, "127.0.0.1", "localhost", 1)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		if want := "/repos/acme/widgets/tarball/" + testSHA; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		http.Redirect(w, r, redirectURL+"/acme/widgets/legacy.tar.gz?token=codeloadSecret", http.StatusFound)
	}))
	t.Cleanup(first.Close)

	rc, err := newTestClient(t, first.URL, nil).Tarball(t.Context(), "acme", "widgets", testSHA)
	if err != nil {
		t.Fatalf("Tarball: %v", err)
	}
	body, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read tarball: %v", err)
	}
	if string(body) != "tarball-bytes" {
		t.Fatalf("body = %q, want tarball-bytes", body)
	}
	if got, _ := redirectedAuth.Load().(string); got != "" {
		t.Fatalf("Authorization forwarded to the redirect host: %q", got)
	}
}

func TestTarballSizeCap(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "chunked body over the cap",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				_, _ = w.Write(bytes.Repeat([]byte("y"), 64))
			},
		},
		{
			name: "content length over the cap",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			client := newTestClient(t, srv.URL, func(cfg *Config) { cfg.MaxTarballBytes = 32 })
			rc, err := client.Tarball(t.Context(), "acme", "widgets", testSHA)
			if err != nil {
				if !strings.Contains(err.Error(), "32 bytes") {
					t.Fatalf("Tarball error = %v, want the size limit", err)
				}
				return
			}
			defer func() { _ = rc.Close() }()

			_, err = io.ReadAll(rc)
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("read error = %v, want *Error", err)
			}
			if !strings.Contains(apiErr.Hint, "32 bytes") {
				t.Fatalf("hint = %q, want the size limit", apiErr.Hint)
			}
		})
	}
}

func TestSecretsNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1700000000")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// The next link carries a codeload-style token, as a redirect URL would.
		w.Header().Set("Link", `<http://`+r.Host+`/user/repos?per_page=100&sort=pushed&page=2&token=codeloadSecret>; rel="next"`)
		_, _ = w.Write([]byte(`[{"full_name":"acme/one"}]`))
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(t, srv.URL, func(cfg *Config) { cfg.Logger = logger })
	_, err := client.ListRepos(t.Context())
	if err == nil {
		t.Fatal("ListRepos succeeded, want a rate-limit error")
	}

	if logs.Len() == 0 {
		t.Fatal("the client wrote no log lines, so the assertion proves nothing")
	}
	for name, text := range map[string]string{
		"logs":  logs.String(),
		"error": err.Error(),
	} {
		for _, secret := range []string{testToken, "codeloadSecret", "token="} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains %q: %s", name, secret, text)
			}
		}
	}
}
