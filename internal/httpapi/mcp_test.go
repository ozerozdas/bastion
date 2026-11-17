package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

func TestGetMCPSetup(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/mcp", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}

	var setup gen.MCPSetup
	if err := json.Unmarshal(readBody(t, resp), &setup); err != nil {
		t.Fatalf("decode MCP setup: %v", err)
	}
	if setup.Command != "/opt/bastion/bin/bastion" {
		t.Errorf("command = %q, want %q", setup.Command, "/opt/bastion/bin/bastion")
	}
	wantArgs := []string{"mcp", "--data-dir"}
	if len(setup.Args) != 3 || setup.Args[0] != wantArgs[0] || setup.Args[1] != wantArgs[1] {
		t.Fatalf("args = %v, want mcp --data-dir <dir>", setup.Args)
	}
	if setup.Args[2] == "" {
		t.Error("args has an empty data directory")
	}
}

// TestMCPSetupWithoutCommandIs500 covers a Server built without serve's
// resolved binary (the zero Config.MCP).
func TestMCPSetupWithoutCommandIs500(t *testing.T) {
	s := &Server{}

	resp, err := s.GetMCPSetup(context.Background(), gen.GetMCPSetupRequestObject{})
	if err != nil {
		t.Fatalf("GetMCPSetup: %v", err)
	}
	if _, ok := resp.(gen.GetMCPSetup500ApplicationProblemPlusJSONResponse); !ok {
		t.Fatalf("response = %T, want 500 problem", resp)
	}
}
