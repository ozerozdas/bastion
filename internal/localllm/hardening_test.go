package localllm

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestExplainReportsBothErrorShapes covers the OpenAI object and Ollama's
// plain string, each answered with HTTP 200.
func TestExplainReportsBothErrorShapes(t *testing.T) {
	for name, body := range map[string]string{
		"object": `{"error":{"message":"model not loaded"}}`,
		"string": `{"error":"model not loaded"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			t.Cleanup(server.Close)

			_, err := enabledService(t, server.URL).Explain(t.Context(), ExplainInput{Title: "x"})
			if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "model not loaded") {
				t.Fatalf("Explain = %v, want ErrUpstream naming the model error", err)
			}
		})
	}
}

// TestExplainKeepsTheCauseOfAnHTTPError covers Ollama's 404 for a model that
// was never pulled: the body's message must survive the status check.
func TestExplainKeepsTheCauseOfAnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"model not found, try pulling it first"}`)
	}))
	t.Cleanup(server.Close)

	_, err := enabledService(t, server.URL).Explain(t.Context(), ExplainInput{Title: "x"})
	if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "try pulling it first") {
		t.Fatalf("Explain = %v, want ErrUpstream naming the cause", err)
	}
}

// TestExplainCapsInFlightRequests holds the model until more callers than
// slots have started, and checks only maxInFlight reach it at once.
func TestExplainCapsInFlightRequests(t *testing.T) {
	var running, peak atomic.Int32
	entered := make(chan struct{}, maxInFlight+2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := running.Add(1)
		defer running.Add(-1)
		for {
			seen := peak.Load()
			if now <= seen || peak.CompareAndSwap(seen, now) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	t.Cleanup(server.Close)

	service := enabledService(t, server.URL)
	var callers sync.WaitGroup
	for range maxInFlight + 2 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if _, err := service.Explain(t.Context(), ExplainInput{Title: "x"}); err != nil {
				t.Errorf("Explain: %v", err)
			}
		}()
	}

	for range maxInFlight {
		<-entered
	}
	// Give a caller that wrongly skipped the cap time to reach the server.
	time.Sleep(100 * time.Millisecond)
	close(release)
	callers.Wait()

	if got := peak.Load(); got != maxInFlight {
		t.Errorf("peak concurrent requests = %d, want %d", got, maxInFlight)
	}
}

// TestShutdownCancelsExplanations proves a running call and one waiting for a
// slot both return at once instead of running to the 60 s timeout.
func TestShutdownCancelsExplanations(t *testing.T) {
	entered := make(chan struct{}, maxInFlight)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// net/http notices a client disconnect only once the body is consumed.
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	service := enabledService(t, server.URL)
	results := make(chan error, maxInFlight+1)
	for range maxInFlight + 1 {
		go func() {
			_, err := service.Explain(t.Context(), ExplainInput{Title: "x"})
			results <- err
		}()
	}
	for range maxInFlight {
		<-entered
	}

	service.Shutdown()
	for range maxInFlight + 1 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrUpstream) {
				t.Errorf("Explain after Shutdown = %v, want ErrUpstream", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Explain did not return after Shutdown")
		}
	}
}

// TestSettingsWriteLeavesOnlyThePrivateFile checks the atomic write's result:
// no temporary file stays behind and the mode is owner-only.
func TestSettingsWriteLeavesOnlyThePrivateFile(t *testing.T) {
	dir := t.TempDir()
	service, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	model := "llama3.1"
	if _, err := service.Update(UpdateInput{Model: &model}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != settingsFileName {
		t.Fatalf("data dir = %v, want only %s", entries, settingsFileName)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}
