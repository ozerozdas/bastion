package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// osvUnavailable is the detail for the OSV endpoints when serve did not wire a
// setting (some tests build a Server without one).
const osvUnavailable = "the OSV online lookup setting is not configured; start bastion with its data directory"

// osvSettings is the part of *osv.Settings the endpoints use. Enabled reports
// the stored choice, on by default; SetEnabled stores the UI's answer.
type osvSettings interface {
	Enabled() bool
	SetEnabled(enabled bool) error
}

// GetOSVStatus implements gen.StrictServerInterface. It reads the stored
// setting only; no request reaches api.osv.dev.
func (s *Server) GetOSVStatus(_ context.Context, _ gen.GetOSVStatusRequestObject) (gen.GetOSVStatusResponseObject, error) {
	if s.osv == nil {
		return gen.GetOSVStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", osvUnavailable),
		}, nil
	}
	return gen.GetOSVStatus200JSONResponse(gen.OSVStatus{Enabled: s.osv.Enabled()}), nil
}

// SetOSVEnabled implements gen.StrictServerInterface. Only the UI calls it; the
// CLI only reads the choice. Turning the lookup off affects the next scan,
// never a running one.
func (s *Server) SetOSVEnabled(_ context.Context, request gen.SetOSVEnabledRequestObject) (gen.SetOSVEnabledResponseObject, error) {
	if s.osv == nil {
		return gen.SetOSVEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", osvUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetOSVEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.osv.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store OSV online lookup setting", "error", err)
		return gen.SetOSVEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the OSV online lookup choice; see the server log"),
		}, nil
	}

	return gen.SetOSVEnabled200JSONResponse(gen.OSVStatus{Enabled: s.osv.Enabled()}), nil
}
