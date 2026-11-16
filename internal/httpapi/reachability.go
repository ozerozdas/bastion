package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/govulncheck"
)

// reachabilityUnavailable is the detail for the reachability endpoints when
// serve did not wire a service (some tests build a Server without one).
const reachabilityUnavailable = "Go reachability is not configured; start bastion with its data directory"

// GetReachabilityStatus implements gen.StrictServerInterface. The probe is a
// PATH lookup only, so this handler never starts a process or waits on the
// network.
func (s *Server) GetReachabilityStatus(_ context.Context, _ gen.GetReachabilityStatusRequestObject) (gen.GetReachabilityStatusResponseObject, error) {
	if s.reachability == nil {
		return gen.GetReachabilityStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reachabilityUnavailable),
		}, nil
	}
	return gen.GetReachabilityStatus200JSONResponse(reachabilityStatusResponse(s.reachability.Status())), nil
}

// SetReachabilityEnabled implements gen.StrictServerInterface. Only the UI
// calls it; the CLI never prompts or writes the choice.
func (s *Server) SetReachabilityEnabled(_ context.Context, request gen.SetReachabilityEnabledRequestObject) (gen.SetReachabilityEnabledResponseObject, error) {
	if s.reachability == nil {
		return gen.SetReachabilityEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reachabilityUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetReachabilityEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.reachability.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store reachability setting", "error", err)
		return gen.SetReachabilityEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the reachability choice; see the server log"),
		}, nil
	}

	return gen.SetReachabilityEnabled200JSONResponse(reachabilityStatusResponse(s.reachability.Status())), nil
}

// reachabilityStatusResponse maps the domain status onto the API shape. Absent
// optional values stay absent rather than becoming "".
func reachabilityStatusResponse(status govulncheck.Status) gen.ReachabilityStatus {
	out := gen.ReachabilityStatus{
		Enabled:   status.Enabled,
		Available: status.Available,
	}
	if status.Error != "" {
		message := status.Error
		out.Error = &message
	}
	return out
}
