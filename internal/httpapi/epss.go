package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// epssUnavailable is the detail for the EPSS endpoints when serve did not wire
// a service (some tests build a Server without one).
const epssUnavailable = "EPSS scores are not configured; start bastion with its data directory"

// GetEPSSStatus implements gen.StrictServerInterface. The service returns the
// cached state immediately and may refresh it in the background, so this
// handler never waits for FIRST.org.
func (s *Server) GetEPSSStatus(_ context.Context, _ gen.GetEPSSStatusRequestObject) (gen.GetEPSSStatusResponseObject, error) {
	if s.epss == nil {
		return gen.GetEPSSStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", epssUnavailable),
		}, nil
	}
	return gen.GetEPSSStatus200JSONResponse(epssStatusResponse(s.epss.Status())), nil
}

// SetEPSSEnabled implements gen.StrictServerInterface. Only the UI calls it;
// the CLI never prompts or writes the choice.
func (s *Server) SetEPSSEnabled(_ context.Context, request gen.SetEPSSEnabledRequestObject) (gen.SetEPSSEnabledResponseObject, error) {
	if s.epss == nil {
		return gen.SetEPSSEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", epssUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetEPSSEnabled400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.epss.SetEnabled(request.Body.Enabled); err != nil {
		s.log.Error("store EPSS setting", "error", err)
		return gen.SetEPSSEnabled500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the EPSS choice; see the server log"),
		}, nil
	}

	return gen.SetEPSSEnabled200JSONResponse(epssStatusResponse(s.epss.Status())), nil
}

// epssStatusResponse maps the domain status onto the API shape. Absent
// optional values stay absent rather than becoming "".
func epssStatusResponse(status epss.Status) gen.EPSSStatus {
	out := gen.EPSSStatus{Enabled: status.Enabled}
	if !status.LastRefresh.IsZero() {
		refreshed := status.LastRefresh
		out.LastRefresh = &refreshed
	}
	if status.ScoreDate != "" {
		scoreDate := status.ScoreDate
		out.ScoreDate = &scoreDate
	}
	if status.Count > 0 {
		count := status.Count
		out.Count = &count
	}
	if status.Error != "" {
		message := status.Error
		out.Error = &message
	}
	return out
}
