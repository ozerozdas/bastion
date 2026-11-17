package mcpserver_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/mcpserver"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

// TestHTTPTransport (#42) serves the tools over streamable HTTP on loopback:
// an MCP client works, a DNS-rebinding Host and a cross-site browser request
// are refused.
func TestHTTPTransport(t *testing.T) {
	db := openTestDB(t)
	seedAsset(t, db, findings.AssetKindRepo, "acme/app", "acme/app")
	server, err := mcpserver.New(mcpserver.Config{
		Assets:  newAssetsService(t, db),
		Reports: newReportsService(t, db),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.HTTPHandler(slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(ts.Close)

	t.Run("client", func(t *testing.T) {
		client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		result := call[envelope[assetsResult]](t, session, "list_assets", nil)
		if result.UntrustedContent != mcpserver.UntrustedNotice || len(result.Data.Assets) != 1 {
			t.Fatalf("list_assets over HTTP = %+v", result)
		}
	})

	refused := []struct {
		name   string
		header map[string]string
		host   string
	}{
		{"rebinding host", nil, "evil.example"},
		{"cross-site browser", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, ""},
		{"cross-origin without fetch metadata", map[string]string{"Origin": "https://evil.example"}, ""},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(initializeBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			if tc.host != "" {
				req.Host = tc.host
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
}
