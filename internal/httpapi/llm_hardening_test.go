package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/localllm"
)

// TestExplainSendsTheRequestedFinding seeds two findings and checks the lookup
// by fingerprint picks the one in the URL.
func TestExplainSendsTheRequestedFinding(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	fake := newFakeModel(t)
	enableLLM(t, ts, cookie, fake.URL+"/v1")

	asset := pathAsset(t, ts, cookie)
	seed := func(rule string) findings.Finding {
		return findings.Finding{
			AssetID:     asset.Id,
			Type:        findings.TypeVulnerability,
			RuleID:      rule,
			Severity:    findings.SeverityHigh,
			Title:       "Title of " + rule,
			Scanner:     "trivy",
			Fingerprint: "fp-" + rule,
		}
	}
	seedSucceededScan(t, ts, asset.Id, seed("CVE-2024-0001"), seed("CVE-2024-0002"))

	resp := doJSON(t, ts, http.MethodPost,
		"/api/assets/"+itoa(asset.Id)+"/findings/"+url.PathEscape("fp-CVE-2024-0002")+"/explain",
		nil, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("explain: status = %d: %s", resp.StatusCode, readBody(t, resp))
	}

	user := llmMessages(t, fake.requestBody())[1].Content
	if !strings.Contains(user, "Title of CVE-2024-0002") || strings.Contains(user, "Title of CVE-2024-0001") {
		t.Errorf("prompt does not carry only the requested finding:\n%s", user)
	}
}

// TestOversizedAPIBodyIsRefused checks the body cap answers 413 problem+json.
func TestOversizedAPIBodyIsRefused(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := doJSON(t, ts, http.MethodPut, "/api/llm", map[string]any{
		"model": strings.Repeat("x", maxAPIBodyBytes+1),
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusRequestEntityTooLarge, readBody(t, resp))
	}
	if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
}

// TestServeShutdownCancelsExplanations proves stopping the server does not
// wait for a slow local model.
func TestServeShutdownCancelsExplanations(t *testing.T) {
	entered := make(chan struct{}, 1)
	model := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// net/http notices a client disconnect only once the body is consumed.
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(model.Close)

	service, err := localllm.New(localllm.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("localllm.New: %v", err)
	}
	enabled, name := true, "llama3.1"
	if _, err := service.Update(localllm.UpdateInput{Enabled: &enabled, Endpoint: &model.URL, Model: &name}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	ln, err := Listen(0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	server, err := New(Config{LLM: service})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, ln) }()

	explained := make(chan error, 1)
	go func() {
		_, err := service.Explain(t.Context(), localllm.ExplainInput{Title: "x"})
		explained <- err
	}()
	<-entered
	stop()

	select {
	case err := <-explained:
		if !errors.Is(err, localllm.ErrUpstream) {
			t.Errorf("Explain = %v, want ErrUpstream", err)
		}
	case <-time.After(shutdownGrace):
		t.Fatal("the explanation outlived the shutdown")
	}
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
}
