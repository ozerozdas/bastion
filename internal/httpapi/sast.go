package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/opengrep"
)

// sastUnavailable is the detail for the SAST endpoints when serve did not wire
// a service (some tests build a Server without one).
const sastUnavailable = "SAST is not configured; start bastion with its data directory"

// GetSASTStatus implements gen.StrictServerInterface. The handler reads the
// setting and the module directory only, so it never waits on a download.
func (s *Server) GetSASTStatus(_ context.Context, _ gen.GetSASTStatusRequestObject) (gen.GetSASTStatusResponseObject, error) {
	if s.sast == nil {
		return gen.GetSASTStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", sastUnavailable),
		}, nil
	}
	return gen.GetSASTStatus200JSONResponse(sastStatusResponse(s.sast.Status())), nil
}

// SetSASTEnabled implements gen.StrictServerInterface. Turning it on starts the
// one-time download in the background; the response reports that it is
// installing, not the finished module.
func (s *Server) SetSASTEnabled(_ context.Context, request gen.SetSASTEnabledRequestObject) (gen.SetSASTEnabledResponseObject, error) {
	if s.sast == nil {
		return gen.SetSASTEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", sastUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetSASTEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.sast.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store SAST setting", "error", err)
		return gen.SetSASTEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the SAST choice; see the server log"),
		}, nil
	}

	return gen.SetSASTEnabled200JSONResponse(sastStatusResponse(s.sast.Status())), nil
}

// sastStatusResponse maps the domain status onto the API shape. Absent
// optional values stay absent rather than becoming "".
func sastStatusResponse(status opengrep.Status) gen.SASTStatus {
	out := gen.SASTStatus{
		Enabled:    status.Enabled,
		State:      gen.SASTState(status.State),
		Version:    status.Version,
		Installing: status.Installing,
	}
	if status.Error != "" {
		message := status.Error
		out.Error = &message
	}
	if status.InstallError != "" {
		message := status.InstallError
		out.InstallError = &message
	}
	return out
}
