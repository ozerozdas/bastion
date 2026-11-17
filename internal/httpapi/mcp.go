package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// mcpUnavailable is the detail for /api/mcp when serve did not resolve the
// running binary (some tests build a Server without one).
const mcpUnavailable = "MCP setup is not available; start bastion with `bastion serve`"

// MCPSetup is the command and arguments GET /api/mcp advertises. serve resolves
// them from the running binary and the resolved data directory.
type MCPSetup struct {
	Command string
	Args    []string
}

// GetMCPSetup implements gen.StrictServerInterface. It reports the command a
// client uses to start `bastion mcp`; nothing is written or started.
func (s *Server) GetMCPSetup(_ context.Context, _ gen.GetMCPSetupRequestObject) (gen.GetMCPSetupResponseObject, error) {
	if s.mcp.Command == "" {
		return gen.GetMCPSetup500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", mcpUnavailable),
		}, nil
	}
	return gen.GetMCPSetup200JSONResponse(gen.MCPSetup{
		Command: s.mcp.Command,
		Args:    s.mcp.Args,
	}), nil
}
