package update

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingTransport counts every request that reaches the httptest server. The
// update package must never create a request when the check is off.
type countingTransport struct {
	base  http.RoundTripper
	mu    sync.Mutex
	count int
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.count++
	t.mu.Unlock()
	return t.base.RoundTrip(req)
}

func (t *countingTransport) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

// fakeClock is a settable clock for cache-expiry tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testEnv owns a checker, a counting transport and the fake clock.
type testEnv struct {
	checker   *Checker
	transport *countingTransport
	clock     *fakeClock
	hits      atomic.Int32
}

// newTestEnv wires a checker against an httptest server. handler defaults to a
// redirect carrying v0.2.0, the common "newer release exists" answer.
func newTestEnv(t *testing.T, handler http.HandlerFunc, tune func(*Config)) *testEnv {
	t.Helper()

	env := &testEnv{clock: &fakeClock{now: time.Date(2026, time.November, 12, 10, 0, 0, 0, time.UTC)}}
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/ozerozdas/bastion/releases/tag/v0.2.0")
			w.WriteHeader(http.StatusFound)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)
		if got, want := r.URL.Path, releasesLatestPath; got != want {
			t.Errorf("request path = %q, want %q", got, want)
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	env.transport = &countingTransport{base: http.DefaultTransport}
	cfg := Config{
		CurrentVersion: "v0.1.0",
		DataDir:        t.TempDir(),
		CacheDir:       t.TempDir(),
		BaseURL:        server.URL,
		HTTPClient:     &http.Client{Transport: env.transport},
		Now:            env.clock.Now,
		Getenv:         func(string) string { return "" },
		Executable:     func() (string, error) { return "/home/me/.local/bin/bastion", nil },
		GOOS:           "darwin",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if tune != nil {
		tune(&cfg)
	}
	env.checker = New(cfg)
	return env
}

func TestTagFromLocation(t *testing.T) {
	tests := []struct {
		name     string
		location string
		wantTag  string
		wantOK   bool
	}{
		{
			name:     "valid",
			location: "https://github.com/ozerozdas/bastion/releases/tag/v0.2.0",
			wantTag:  "v0.2.0",
			wantOK:   true,
		},
		{
			name:     "valid without v",
			location: "https://github.com/ozerozdas/bastion/releases/tag/0.2.0",
			wantTag:  "0.2.0",
			wantOK:   true,
		},
		{
			name:     "relative",
			location: "/ozerozdas/bastion/releases/tag/v0.2.0",
			wantTag:  "v0.2.0",
			wantOK:   true,
		},
		{
			name:     "missing",
			location: "https://github.com/ozerozdas/bastion/releases",
		},
		{
			name:     "empty",
			location: "",
		},
		{
			name:     "malformed url",
			location: "://not-a-url",
		},
		{
			name:     "empty tag",
			location: "https://github.com/ozerozdas/bastion/releases/tag/",
		},
		{
			name:     "extra path segment",
			location: "https://github.com/ozerozdas/bastion/releases/tag/v0.2.0/notes",
		},
		{
			name:     "not semver",
			location: "https://github.com/ozerozdas/bastion/releases/tag/latest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tag, ok := tagFromLocation(tc.location)
			if ok != tc.wantOK {
				t.Fatalf("tagFromLocation(%q) ok = %v, want %v", tc.location, ok, tc.wantOK)
			}
			if tag != tc.wantTag {
				t.Errorf("tagFromLocation(%q) = %q, want %q", tc.location, tag, tc.wantTag)
			}
		})
	}
}

func TestNewerThan(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{name: "newer", current: "v0.1.0", latest: "v0.1.1", want: true},
		{name: "equal", current: "v0.1.0", latest: "v0.1.0", want: false},
		{name: "older", current: "v0.2.0", latest: "v0.1.9", want: false},
		{name: "current without v", current: "0.1.0", latest: "v0.1.1", want: true},
		{name: "latest without v", current: "v0.1.0", latest: "0.1.1", want: true},
		{name: "dev build", current: "dev", latest: "v0.1.1", want: false},
		{name: "invalid latest", current: "v0.1.0", latest: "nightly", want: false},
		{name: "prerelease is older", current: "v0.1.1", latest: "v0.1.1-rc.1", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := newerThan(tc.current, tc.latest); got != tc.want {
				t.Errorf("newerThan(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

func TestInstallCommandFor(t *testing.T) {
	tests := []struct {
		name string
		path string
		goos string
		want string
	}{
		{
			name: "macOS cask",
			path: "/opt/homebrew/Caskroom/bastion/0.1.0/bastion",
			goos: "darwin",
			want: brewCommand,
		},
		{
			name: "macOS Homebrew bin",
			path: "/opt/homebrew/bin/bastion",
			goos: "darwin",
			want: brewCommand,
		},
		{
			name: "Linuxbrew",
			path: "/home/linuxbrew/.linuxbrew/bin/bastion",
			goos: "linux",
			want: brewCommand,
		},
		{
			name: "macOS script install",
			path: "/Users/me/.local/bin/bastion",
			goos: "darwin",
			want: installCommand,
		},
		{
			name: "Linux script install",
			path: "/home/me/.local/bin/bastion",
			goos: "linux",
			want: installCommand,
		},
		{
			name: "windows has no command",
			path: `C:\Users\me\bin\bastion.exe`,
			goos: "windows",
			want: "",
		},
		{
			name: "windows ignores Homebrew path",
			path: "/opt/homebrew/bin/bastion",
			goos: "windows",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := installCommandFor(tc.path, tc.goos); got != tc.want {
				t.Errorf("installCommandFor(%q, %q) = %q, want %q", tc.path, tc.goos, got, tc.want)
			}
		})
	}
}

func TestConsentRoundTrip(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	if got := env.checker.Consent(); got != ConsentUnset {
		t.Fatalf("Consent() = %q, want %q before any answer", got, ConsentUnset)
	}

	if err := env.checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}
	if got := env.checker.Consent(); got != ConsentOn {
		t.Errorf("Consent() = %q, want %q", got, ConsentOn)
	}
	info, err := os.Stat(filepath.Join(env.checker.dataDir, consentFileName))
	if err != nil {
		t.Fatalf("consent file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("consent file mode = %o, want 600", perm)
	}

	if err := env.checker.SetConsent(false); err != nil {
		t.Fatalf("SetConsent(false): %v", err)
	}
	if got := env.checker.Consent(); got != ConsentOff {
		t.Errorf("Consent() = %q, want %q", got, ConsentOff)
	}
}

func TestConsentFailsClosed(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	for _, content := range []string{`not json`, `{"consent":"maybe"}`, `{}`} {
		if err := os.MkdirAll(env.checker.dataDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(env.checker.dataDir, consentFileName), []byte(content), 0o600); err != nil {
			t.Fatalf("write consent file: %v", err)
		}
		if got := env.checker.Consent(); got != ConsentUnset {
			t.Errorf("Consent() with %q = %q, want %q", content, got, ConsentUnset)
		}
	}
}

func TestCheckNowDoesNotRequestWithoutConsent(t *testing.T) {
	tests := []struct {
		name    string
		consent Consent
	}{
		{name: "unset", consent: ConsentUnset},
		{name: "off", consent: ConsentOff},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, nil, nil)
			if tc.consent == ConsentOff {
				if err := env.checker.SetConsent(false); err != nil {
					t.Fatalf("SetConsent(false): %v", err)
				}
			}

			status := env.checker.CheckNow(context.Background())

			if got := env.hits.Load(); got != 0 {
				t.Fatalf("requests = %d, want 0 with consent %q", got, tc.consent)
			}
			if got := env.transport.Count(); got != 0 {
				t.Fatalf("transport requests = %d, want 0", got)
			}
			if status.UpdateAvailable || status.Latest != "" {
				t.Errorf("status = %+v, want no update", status)
			}
		})
	}
}

func TestCheckNowRequestsAtMostOncePerDay(t *testing.T) {
	var userAgent string
	var once sync.Once
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { userAgent = r.Header.Get("User-Agent") })
		w.Header().Set("Location", "/ozerozdas/bastion/releases/tag/v0.2.0")
		w.WriteHeader(http.StatusFound)
	}, nil)
	if err := env.checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}

	status := env.checker.CheckNow(context.Background())
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("first check requests = %d, want 1", got)
	}
	if got, want := userAgent, "bastion/v0.1.0"; got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
	if !status.UpdateAvailable {
		t.Fatalf("status.UpdateAvailable = false, want true: %+v", status)
	}
	if got, want := status.Latest, "v0.2.0"; got != want {
		t.Errorf("Latest = %q, want %q", got, want)
	}
	if got, want := status.ReleaseURL, releasesTagBase+"v0.2.0"; got != want {
		t.Errorf("ReleaseURL = %q, want %q", got, want)
	}
	if status.Command == "" {
		t.Error("Command is empty for a script install")
	}

	// Inside the 24-hour window the cache is used, even though the result is
	// already known to be newer.
	env.clock.Advance(23 * time.Hour)
	env.checker.CheckNow(context.Background())
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("check after 23h requests = %d, want 1", got)
	}

	// At the 24-hour boundary a new request is allowed.
	env.clock.Advance(time.Hour)
	env.checker.CheckNow(context.Background())
	if got := env.hits.Load(); got != 2 {
		t.Fatalf("check after 24h requests = %d, want 2", got)
	}
}

func TestCheckNowCachesFailureSilently(t *testing.T) {
	var logs bytes.Buffer
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}, func(cfg *Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	if err := env.checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}

	status := env.checker.CheckNow(context.Background())
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if status.Latest != "" || status.UpdateAvailable {
		t.Errorf("status = %+v, want no latest after a failed check", status)
	}
	if status.CheckedAt.IsZero() {
		t.Error("CheckedAt is zero; a failed check must still consume the daily budget")
	}

	// The failure is cached: one request per day, not one per call.
	env.checker.CheckNow(context.Background())
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("requests after cached failure = %d, want 1", got)
	}

	if !strings.Contains(logs.String(), "update check failed") {
		t.Errorf("debug log does not mention the failure:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("failed check must not log at error level:\n%s", logs.String())
	}
}

func TestCheckNowDisabled(t *testing.T) {
	tests := []struct {
		name    string
		version string
		env     map[string]string
	}{
		{name: "BASTION_NO_UPDATE_CHECK", version: "v0.1.0", env: map[string]string{EnvNoUpdateCheck: "1"}},
		{name: "CI", version: "v0.1.0", env: map[string]string{"CI": "true"}},
		{name: "dev version", version: "dev"},
		{name: "not semver", version: "abc1234"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, nil, func(cfg *Config) {
				cfg.CurrentVersion = tc.version
				cfg.Getenv = func(name string) string { return tc.env[name] }
			})
			if err := env.checker.SetConsent(true); err != nil {
				t.Fatalf("SetConsent(true): %v", err)
			}

			status := env.checker.CheckNow(context.Background())

			if got := env.hits.Load(); got != 0 {
				t.Fatalf("requests = %d, want 0 when the check is disabled", got)
			}
			if status.Disabled == "" {
				t.Error("Disabled is empty, want a reason")
			}
		})
	}
}

func TestSnapshotDoesNotRequest(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	if err := env.checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}

	env.checker.Snapshot()

	if got := env.hits.Load(); got != 0 {
		t.Fatalf("Snapshot requests = %d, want 0", got)
	}
}

func TestStatusRefreshesInBackgroundWhenStale(t *testing.T) {
	requested := make(chan struct{}, 1)
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		w.Header().Set("Location", "/ozerozdas/bastion/releases/tag/v0.2.0")
		w.WriteHeader(http.StatusFound)
	}, nil)
	if err := env.checker.SetConsent(true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}

	start := time.Now()
	status := env.checker.Status()
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Status() blocked for %s waiting for the network", elapsed)
	}
	if status.Latest != "" {
		t.Errorf("Status() returned Latest = %q before the check finished", status.Latest)
	}

	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("background check made no request")
	}

	// Wait for the cache write, then a second Status must reuse it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.checker.Snapshot().Latest != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := env.checker.Snapshot().Latest; got != "v0.2.0" {
		t.Fatalf("cached Latest = %q, want v0.2.0", got)
	}

	env.checker.Status()
	time.Sleep(50 * time.Millisecond)
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1; the fresh cache must suppress a second check", got)
	}
}
