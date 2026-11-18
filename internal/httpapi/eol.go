package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// eolUnavailable is the detail when serve did not wire a service.
const eolUnavailable = "end-of-life lookup is not configured; start bastion with its data directory"

// GetEOLStatus implements gen.StrictServerInterface. It reads the stored
// setting only; no request reaches endoflife.date.
func (s *Server) GetEOLStatus(_ context.Context, _ gen.GetEOLStatusRequestObject) (gen.GetEOLStatusResponseObject, error) {
	if s.eol == nil {
		return gen.GetEOLStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", eolUnavailable),
		}, nil
	}
	return gen.GetEOLStatus200JSONResponse(gen.EOLStatus{Enabled: s.eol.Snapshot().Enabled}), nil
}

// SetEOLEnabled implements gen.StrictServerInterface.
func (s *Server) SetEOLEnabled(_ context.Context, request gen.SetEOLEnabledRequestObject) (gen.SetEOLEnabledResponseObject, error) {
	if s.eol == nil {
		return gen.SetEOLEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", eolUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetEOLEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}
	if err := s.eol.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store end-of-life lookup setting", "error", err)
		return gen.SetEOLEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the end-of-life lookup choice; see the server log"),
		}, nil
	}
	return gen.SetEOLEnabled200JSONResponse(gen.EOLStatus{Enabled: s.eol.Snapshot().Enabled}), nil
}
