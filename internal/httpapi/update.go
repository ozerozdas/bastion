package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/update"
)

// updateUnavailable is the detail for the update endpoints when serve did not
// wire a checker (some tests build a Server without one).
const updateUnavailable = "release checking is not configured; start bastion with its data directory"

// GetUpdateStatus implements gen.StrictServerInterface. The checker returns the
// cached value immediately and may refresh it in the background, so this
// handler never waits for github.com.
func (s *Server) GetUpdateStatus(_ context.Context, _ gen.GetUpdateStatusRequestObject) (gen.GetUpdateStatusResponseObject, error) {
	if s.update == nil {
		return gen.GetUpdateStatus500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", updateUnavailable),
		}, nil
	}
	return gen.GetUpdateStatus200JSONResponse(updateStatusResponse(s.update.Status())), nil
}

// SetUpdateConsent implements gen.StrictServerInterface. Only the UI calls it;
// the CLI never prompts or writes the choice.
func (s *Server) SetUpdateConsent(_ context.Context, request gen.SetUpdateConsentRequestObject) (gen.SetUpdateConsentResponseObject, error) {
	if s.update == nil {
		return gen.SetUpdateConsent500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", updateUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetUpdateConsent400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	if err := s.update.SetConsent(request.Body.Enabled); err != nil {
		s.log.Error("store update consent", "error", err)
		return gen.SetUpdateConsent500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the release-check choice; see the server log"),
		}, nil
	}

	return gen.SetUpdateConsent200JSONResponse(updateStatusResponse(s.update.Status())), nil
}

// updateStatusResponse maps the domain status onto the API shape. Absent
// optional values stay absent rather than becoming "".
func updateStatusResponse(status update.Status) gen.UpdateStatus {
	out := gen.UpdateStatus{
		Current:         status.Current,
		UpdateAvailable: status.UpdateAvailable,
		Consent:         gen.UpdateConsent(status.Consent),
		Disabled:        status.Disabled != "",
	}
	if status.Latest != "" {
		out.Latest = &status.Latest
	}
	if status.Command != "" {
		out.Command = &status.Command
	}
	if status.ReleaseURL != "" {
		out.ReleaseUrl = &status.ReleaseURL
	}
	return out
}
