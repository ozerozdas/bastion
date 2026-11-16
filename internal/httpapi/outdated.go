package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/depsdev"
)

// outdatedUnavailable is the detail for the outdated endpoints when serve did
// not wire a service (some tests build a Server without one).
const outdatedUnavailable = "outdated-package lookup is not configured; start bastion with its data directory"

// GetOutdatedStatus implements gen.StrictServerInterface. It reads the stored
// setting only; no request reaches deps.dev.
func (s *Server) GetOutdatedStatus(_ context.Context, _ gen.GetOutdatedStatusRequestObject) (gen.GetOutdatedStatusResponseObject, error) {
	if s.outdated == nil {
		return gen.GetOutdatedStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", outdatedUnavailable),
		}, nil
	}
	return gen.GetOutdatedStatus200JSONResponse(outdatedStatusResponse(s.outdated.Snapshot())), nil
}

// SetOutdatedEnabled implements gen.StrictServerInterface. Only the UI calls
// it; the CLI never prompts or writes the choice.
func (s *Server) SetOutdatedEnabled(_ context.Context, request gen.SetOutdatedEnabledRequestObject) (gen.SetOutdatedEnabledResponseObject, error) {
	if s.outdated == nil {
		return gen.SetOutdatedEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", outdatedUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetOutdatedEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.outdated.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store outdated lookup setting", "error", err)
		return gen.SetOutdatedEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the outdated lookup choice; see the server log"),
		}, nil
	}

	return gen.SetOutdatedEnabled200JSONResponse(outdatedStatusResponse(s.outdated.Snapshot())), nil
}

// outdatedStatusResponse maps the domain status onto the API shape.
func outdatedStatusResponse(status depsdev.Status) gen.OutdatedStatus {
	return gen.OutdatedStatus{Enabled: status.Enabled}
}
