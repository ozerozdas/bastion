package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// The handlers in this file stay thin (PROJECT_SPEC.md §9.2): decode, call the
// connections service, map domain errors to problem+json. Validation of names,
// tokens and GitHub behaviour lives in the service.

// unavailable is the detail for endpoints that need the service but were built
// without one.
const unavailable = "connections are not configured; start bastion with its database"

// ListConnections implements gen.StrictServerInterface.
func (s *Server) ListConnections(ctx context.Context, _ gen.ListConnectionsRequestObject) (gen.ListConnectionsResponseObject, error) {
	if s.connections == nil {
		return gen.ListConnections500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", unavailable),
		}, nil
	}
	list, err := s.connections.List(ctx)
	if err != nil {
		s.log.Error("list connections", "error", err)
		return gen.ListConnections500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the connections; see the server log"),
		}, nil
	}

	out := make([]gen.Connection, 0, len(list))
	for _, conn := range list {
		out = append(out, connectionResponse(conn))
	}
	return gen.ListConnections200JSONResponse{Connections: out}, nil
}

// CreateConnection implements gen.StrictServerInterface.
func (s *Server) CreateConnection(ctx context.Context, request gen.CreateConnectionRequestObject) (gen.CreateConnectionResponseObject, error) {
	if s.connections == nil {
		return gen.CreateConnection500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", unavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.CreateConnection400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}
	var token string
	if request.Body.Token != nil {
		token = *request.Body.Token
	}

	conn, err := s.connections.Create(ctx, connections.CreateInput{
		Kind:  string(request.Body.Kind),
		Name:  request.Body.Name,
		Token: token,
	})
	if err != nil {
		s.log.Error("create connection", "error", err)
		status, problem := connectionProblem(err, 0)
		switch status {
		case http.StatusBadRequest:
			return gen.CreateConnection400ApplicationProblemPlusJSONResponse{
				ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{Body: problem},
			}, nil
		case http.StatusConflict:
			return gen.CreateConnection409ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.CreateConnection500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.CreateConnection201JSONResponse(connectionResponse(conn)), nil
}

// DeleteConnection implements gen.StrictServerInterface.
func (s *Server) DeleteConnection(ctx context.Context, request gen.DeleteConnectionRequestObject) (gen.DeleteConnectionResponseObject, error) {
	if s.connections == nil {
		return gen.DeleteConnection500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", unavailable),
		}, nil
	}
	if err := s.connections.Delete(ctx, request.Id); err != nil {
		s.log.Error("delete connection", "id", request.Id, "error", err)
		status, problem := connectionProblem(err, request.Id)
		if status == http.StatusNotFound {
			return gen.DeleteConnection404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
		return gen.DeleteConnection500ApplicationProblemPlusJSONResponse{Body: problem}, nil
	}
	return gen.DeleteConnection204Response{}, nil
}

// TestConnection implements gen.StrictServerInterface.
func (s *Server) TestConnection(ctx context.Context, request gen.TestConnectionRequestObject) (gen.TestConnectionResponseObject, error) {
	if s.connections == nil {
		return gen.TestConnection500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", unavailable),
		}, nil
	}
	conn, err := s.connections.Test(ctx, request.Id)
	if err != nil {
		s.log.Error("test connection", "id", request.Id, "error", err)
		status, problem := connectionProblem(err, request.Id)
		switch status {
		case http.StatusBadRequest:
			return gen.TestConnection400ApplicationProblemPlusJSONResponse{
				ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{Body: problem},
			}, nil
		case http.StatusNotFound:
			return gen.TestConnection404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		default:
			return gen.TestConnection500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.TestConnection200JSONResponse(connectionResponse(conn)), nil
}

// DiscoverConnectionRepos implements gen.StrictServerInterface.
func (s *Server) DiscoverConnectionRepos(ctx context.Context, request gen.DiscoverConnectionReposRequestObject) (gen.DiscoverConnectionReposResponseObject, error) {
	if s.connections == nil {
		return gen.DiscoverConnectionRepos500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", unavailable),
		}, nil
	}
	repos, err := s.connections.Discover(ctx, request.Id)
	if err != nil {
		s.log.Error("discover connection repositories", "id", request.Id, "error", err)
		status, problem := connectionProblem(err, request.Id)
		switch status {
		case http.StatusBadRequest:
			return gen.DiscoverConnectionRepos400ApplicationProblemPlusJSONResponse{
				ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{Body: problem},
			}, nil
		case http.StatusNotFound:
			return gen.DiscoverConnectionRepos404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		case http.StatusConflict:
			return gen.DiscoverConnectionRepos409ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusBadGateway:
			return gen.DiscoverConnectionRepos502ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.DiscoverConnectionRepos500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}

	out := make([]gen.DiscoveredRepo, 0, len(repos))
	for _, repo := range repos {
		out = append(out, gen.DiscoveredRepo{
			FullName:      repo.FullName,
			DefaultBranch: repo.DefaultBranch,
			Private:       repo.Private,
			Archived:      repo.Archived,
			AlreadyAdded:  repo.AlreadyAdded,
		})
	}
	return gen.DiscoverConnectionRepos200JSONResponse{Repos: out}, nil
}

// connectionProblem maps service errors to problem details and an HTTP status.
// The detail is a user-facing hint; raw errors are only logged by the caller.
func connectionProblem(err error, id int64) (int, gen.Problem) {
	title := "Internal Server Error"
	detail := "the request failed; see the server log"
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, connections.ErrNotFound):
		status, title = http.StatusNotFound, "Not Found"
		detail = "connection not found"
		if id > 0 {
			detail = fmt.Sprintf("connection %d not found", id)
		}
	case errors.Is(err, connections.ErrConflict):
		status, title = http.StatusConflict, "Conflict"
		detail = err.Error()
	case errors.Is(err, connections.ErrInvalid):
		status, title = http.StatusBadRequest, "Bad Request"
		detail = err.Error()
	case errors.Is(err, connections.ErrUnsupportedKind):
		status, title = http.StatusBadRequest, "Bad Request"
		detail = err.Error()
	case errors.Is(err, connections.ErrNoToken):
		status, title = http.StatusConflict, "Conflict"
		detail = connections.Hint(err)
	case errors.Is(err, connections.ErrUpstream):
		status, title = http.StatusBadGateway, "Bad Gateway"
		detail = connections.Hint(err)
	}
	return status, newProblem(status, title, detail)
}

// connectionResponse drops the credential fields and copies the non-secret
// identity into the API shape.
func connectionResponse(conn connections.Connection) gen.Connection {
	out := gen.Connection{
		Id:            conn.ID,
		Kind:          gen.ConnectionKind(conn.Kind),
		Name:          conn.Name,
		Status:        gen.ConnectionStatus(conn.Status),
		CreatedAt:     conn.CreatedAt,
		LastCheckedAt: conn.LastCheckedAt,
	}
	if conn.Login != "" {
		login := conn.Login
		out.Login = &login
	}
	if conn.Hint != "" {
		hint := conn.Hint
		out.Hint = &hint
	}
	return out
}
