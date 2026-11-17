package localllm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNormalizeEndpointRefusesNonLoopbackHosts is the ADR-003 boundary: only
// http(s) on a loopback IP literal or localhost is accepted.
func TestNormalizeEndpointRefusesNonLoopbackHosts(t *testing.T) {
	accepted := []string{
		"http://127.0.0.1:11434/v1",
		"http://127.0.0.1:11434/v1/",
		"https://localhost:8443/v1",
		"http://[::1]:11434/v1",
		" http://127.1.2.3:11434/v1 ",
	}
	for _, raw := range accepted {
		if _, err := NormalizeEndpoint(raw); err != nil {
			t.Errorf("NormalizeEndpoint(%q) = %v, want accepted", raw, err)
		}
	}

	refused := []string{
		"",
		"http://example.com/v1",
		"http://localhost.example.com/v1",
		"http://127.0.0.1.nip.io/v1",
		"http://192.168.1.10:11434/v1",
		"http://10.0.0.5:11434/v1",
		"http://0.0.0.0:11434/v1",
		"http://169.254.1.1/v1",
		"ftp://127.0.0.1/v1",
		"file:///tmp/model",
		"127.0.0.1:11434/v1",
		"http://user:pass@127.0.0.1/v1",
		"http://127.0.0.1/v1?x=1",
		"http://127.0.0.1/v1#fragment",
	}
	for _, raw := range refused {
		if endpoint, err := NormalizeEndpoint(raw); err == nil {
			t.Errorf("NormalizeEndpoint(%q) = %q, want refused", raw, endpoint)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeEndpoint(%q) error = %v, want ErrInvalid", raw, err)
		}
	}
}

// TestUpdateRefusesNonLoopbackEndpoint proves the check also happens on save,
// not only before a request.
func TestUpdateRefusesNonLoopbackEndpoint(t *testing.T) {
	service := newService(t)
	for _, endpoint := range []string{
		"http://example.com/v1",
		"http://192.168.0.2:11434/v1",
		"http://0.0.0.0:11434/v1",
	} {
		value := endpoint
		if _, err := service.Update(UpdateInput{Endpoint: &value}); !errors.Is(err, ErrInvalid) {
			t.Errorf("Update(endpoint %q) = %v, want ErrInvalid", endpoint, err)
		}
	}
	if got := service.Settings().Endpoint; got != DefaultEndpoint {
		t.Errorf("endpoint after refused updates = %q, want the default %q", got, DefaultEndpoint)
	}
}

// TestSettingsRoundTrip covers the defaults, a partial update and reload.
func TestSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	service, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := service.Settings(); got != DefaultSettings() {
		t.Fatalf("initial settings = %+v, want %+v", got, DefaultSettings())
	}

	enabled := true
	endpoint := "http://127.0.0.1:1234/v1/"
	model := "  llama3.1  "
	stored, err := service.Update(UpdateInput{Enabled: &enabled, Endpoint: &endpoint, Model: &model})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !stored.Enabled || stored.Endpoint != "http://127.0.0.1:1234/v1" || stored.Model != "llama3.1" {
		t.Fatalf("stored settings = %+v", stored)
	}

	reloaded, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Settings(); got != stored {
		t.Errorf("reloaded settings = %+v, want %+v", got, stored)
	}

	// A hand-edited non-loopback endpoint is replaced by the default on read.
	path := filepath.Join(dir, settingsFileName)
	if err := os.WriteFile(path, []byte(`{"enabled":true,"endpoint":"http://example.com/v1","model":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err = New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("reload edited file: %v", err)
	}
	if got := reloaded.Settings().Endpoint; got != DefaultEndpoint {
		t.Errorf("edited endpoint = %q, want the default", got)
	}
}

func TestExplainRequiresEnabledAndModel(t *testing.T) {
	service := newService(t)
	if _, err := service.Explain(t.Context(), ExplainInput{Title: "x"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Explain with the switch off = %v, want ErrDisabled", err)
	}

	enabled := true
	if _, err := service.Update(UpdateInput{Enabled: &enabled}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := service.Explain(t.Context(), ExplainInput{Title: "x"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Explain without a model = %v, want ErrNotConfigured", err)
	}
}

// TestExplainPostsFixedPrompt calls a fake local server and checks the wire
// shape: fixed system message, untrusted block, no tools and the output cap.
func TestExplainPostsFixedPrompt(t *testing.T) {
	var captured chatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request = %s %s, want POST /v1/chat/completions", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Patch to 1.2.3."}}]}`)
	}))
	t.Cleanup(server.Close)

	service := newService(t)
	enabled := true
	endpoint := server.URL + "/v1"
	model := "llama3.1"
	if _, err := service.Update(UpdateInput{Enabled: &enabled, Endpoint: &endpoint, Model: &model}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	result, err := service.Explain(t.Context(), ExplainInput{
		Title:          "CVE-2024-0001 in lodash",
		RuleID:         "CVE-2024-0001",
		PackageName:    "lodash",
		PackageVersion: "4.17.0",
		FixedVersion:   "4.17.21",
		Location:       "package-lock.json:1",
		Severity:       "high",
		Description:    "A long description.",
		EPSS:           &EPSS{Score: 0.42, Percentile: 0.81},
	})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if result.Text != "Patch to 1.2.3." || result.Model != model {
		t.Errorf("result = %+v", result)
	}

	if len(captured.Messages) != 2 {
		t.Fatalf("messages = %d, want system and user", len(captured.Messages))
	}
	if captured.Messages[0].Role != "system" || captured.Messages[0].Content != SystemPrompt {
		t.Errorf("system message = %q, want the fixed prompt", captured.Messages[0].Content)
	}
	user := captured.Messages[1].Content
	open := strings.Index(user, untrustedOpen)
	closeIdx := strings.Index(user, untrustedClose)
	if open < 0 || closeIdx < open {
		t.Fatalf("user message has no untrusted block:\n%s", user)
	}
	block := user[open+len(untrustedOpen) : closeIdx]
	for _, want := range []string{"CVE-2024-0001", "lodash", "4.17.21", "0.42"} {
		if !strings.Contains(block, want) {
			t.Errorf("untrusted block does not carry %q:\n%s", want, block)
		}
	}
	if captured.Stream {
		t.Error("stream = true, want a non-streaming request")
	}
	if captured.MaxTokens != maxTokens {
		t.Errorf("max_tokens = %d, want %d", captured.MaxTokens, maxTokens)
	}
}

// TestExplainCapsTheAnswer checks the output budget.
func TestExplainCapsTheAnswer(t *testing.T) {
	long := strings.Repeat("advisory text ", 2000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response, err := json.Marshal(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{"content": long},
			}},
		})
		if err != nil {
			t.Errorf("encode fake response: %v", err)
		}
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)

	service := enabledService(t, server.URL)
	result, err := service.Explain(t.Context(), ExplainInput{Title: "x"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(result.Text) > MaxTextBytes {
		t.Errorf("text is %d bytes, want at most %d", len(result.Text), MaxTextBytes)
	}
	if !strings.HasSuffix(result.Text, TruncatedMarker) {
		t.Errorf("text does not end with the truncation marker")
	}
}

// TestExplainRefusesRedirects proves the client cannot be sent to another
// host, even one the local server names.
func TestExplainRefusesRedirects(t *testing.T) {
	var reached bool
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		reached = true
		mu.Unlock()
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"x"}}]}`)
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	service := enabledService(t, redirector.URL)
	_, err := service.Explain(t.Context(), ExplainInput{Title: "x"})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("Explain through a redirect = %v, want ErrUpstream", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reached {
		t.Error("the redirect target was called; redirects must be refused")
	}
}

// TestExplainTimesOut checks that a slow local model cannot hold a request
// past the configured timeout.
func TestExplainTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	t.Cleanup(server.Close)

	service, err := New(Config{DataDir: t.TempDir(), Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	enabled := true
	endpoint := server.URL
	model := "llama3.1"
	if _, err := service.Update(UpdateInput{Enabled: &enabled, Endpoint: &endpoint, Model: &model}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, err := service.Explain(context.Background(), ExplainInput{Title: "x"}); !errors.Is(err, ErrUpstream) {
		t.Fatalf("Explain against a slow server = %v, want ErrUpstream", err)
	}
}

// TestExplainCapsTheResponseBody proves a huge answer is refused before it is
// decoded.
func TestExplainCapsTheResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
	}))
	t.Cleanup(server.Close)

	service := enabledService(t, server.URL)
	if _, err := service.Explain(t.Context(), ExplainInput{Title: "x"}); !errors.Is(err, ErrUpstream) {
		t.Fatalf("Explain against an oversized response = %v, want ErrUpstream", err)
	}
}

// TestClipPreservesValidUTF8 checks the byte budget never splits a rune.
func TestClipPreservesValidUTF8(t *testing.T) {
	limit := len(TruncatedMarker) + 6
	got := clip(strings.Repeat("ş", 100), limit)
	if len(got) > limit {
		t.Errorf("clip returned %d bytes, want at most %d", len(got), limit)
	}
	if !strings.HasSuffix(got, TruncatedMarker) {
		t.Errorf("clip did not add the marker: %q", got)
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("clip introduced a replacement character: %q", got)
	}
}

func newService(t *testing.T) *Service {
	t.Helper()
	service, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return service
}

func enabledService(t *testing.T, endpoint string) *Service {
	t.Helper()
	service := newService(t)
	enabled := true
	model := "llama3.1"
	if _, err := service.Update(UpdateInput{Enabled: &enabled, Endpoint: &endpoint, Model: &model}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return service
}

func TestDialLiteralPinsLocalhost(t *testing.T) {
	cases := map[string]string{
		"http://localhost:11434/v1": "http://127.0.0.1:11434/v1",
		"http://LOCALHOST/v1":       "http://127.0.0.1/v1",
		"http://127.0.0.1:8080/v1":  "http://127.0.0.1:8080/v1",
		"http://[::1]:8080/v1":      "http://[::1]:8080/v1",
	}
	for in, want := range cases {
		if got := dialLiteral(in); got != want {
			t.Errorf("dialLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}
