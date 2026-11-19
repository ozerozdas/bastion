package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// newFakeModelList is an OpenAI-compatible server answering GET /models with a
// fixed, unsorted list that repeats an id.
func newFakeModelList(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q, want /v1/models", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"qwen3:14b"},{"id":"llama3.1"},{"id":"mistral-nemo"},{"id":"llama3.1"}]}`)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestLLMModelsListsSortedAndDeduped covers the listing contract: the saved
// endpoint is used when the query omits one, and the ids come back sorted and
// deduplicated.
func TestLLMModelsListsSortedAndDeduped(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	fake := newFakeModelList(t)
	enableLLM(t, ts, cookie, fake.URL+"/v1")

	resp := ts.do(t, http.MethodGet, "/api/llm/models", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/llm/models: status = %d, want %d: %s",
			resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var listed gen.LLMModels
	if err := json.Unmarshal(readBody(t, resp), &listed); err != nil {
		t.Fatalf("decode models: %v", err)
	}
	want := []string{"llama3.1", "mistral-nemo", "qwen3:14b"}
	if len(listed.Models) != len(want) {
		t.Fatalf("models = %v, want %v", listed.Models, want)
	}
	for i := range want {
		if listed.Models[i] != want[i] {
			t.Fatalf("models = %v, want %v", listed.Models, want)
		}
	}

	// An explicit endpoint is asked instead of the saved one.
	resp = ts.do(t, http.MethodGet, "/api/llm/models?endpoint="+fake.URL+"/v1", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with endpoint: status = %d, want %d: %s",
			resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
}

// TestLLMModelsRefusesNonLoopbackEndpoint proves the listing path reuses the
// save-time validation: a non-loopback endpoint is a 400 and nothing is dialed.
func TestLLMModelsRefusesNonLoopbackEndpoint(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	for _, endpoint := range []string{
		"http://example.com/v1",
		"http://192.168.1.10:11434/v1",
		"ftp://127.0.0.1/v1",
	} {
		resp := ts.do(t, http.MethodGet, "/api/llm/models?endpoint="+endpoint, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET endpoint %q: status = %d, want %d: %s",
				endpoint, resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
		}
		if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("Content-Type = %q, want application/problem+json", got)
		}
	}
}

// TestLLMModelsReportsAnUpstreamFailure checks an unreachable saved endpoint is
// a 502 problem, not a leaked transport error.
func TestLLMModelsReportsAnUpstreamFailure(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"message":"no model registry"}}`)
	}))
	t.Cleanup(failing.Close)

	resp := ts.do(t, http.MethodGet, "/api/llm/models?endpoint="+failing.URL, withCookie(cookie))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusBadGateway, readBody(t, resp))
	}
	if detail := readProblem(t, resp).Detail; detail == nil || *detail == "" {
		t.Error("the 502 problem has no detail")
	}
}
