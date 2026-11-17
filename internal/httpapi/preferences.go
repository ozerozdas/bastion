package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/preferences"
)

// preferencesUnavailable is the detail for the preference endpoints when serve
// did not wire a service (some tests build a Server without one).
const preferencesUnavailable = "preferences are not configured; start bastion with its database"

// GetPreferences implements gen.StrictServerInterface. A key without a value
// is absent from the response.
func (s *Server) GetPreferences(ctx context.Context, _ gen.GetPreferencesRequestObject) (gen.GetPreferencesResponseObject, error) {
	if s.preferences == nil {
		return gen.GetPreferences500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", preferencesUnavailable),
		}, nil
	}

	stored, err := s.preferences.Get(ctx)
	if err != nil {
		s.log.Error("read preferences", "error", err)
		return gen.GetPreferences500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read preferences; see the server log"),
		}, nil
	}
	return gen.GetPreferences200JSONResponse(stored), nil
}

// SetPreferences implements gen.StrictServerInterface. The body merges into
// the stored set: keys it omits are untouched.
func (s *Server) SetPreferences(ctx context.Context, request gen.SetPreferencesRequestObject) (gen.SetPreferencesResponseObject, error) {
	if s.preferences == nil {
		return gen.SetPreferences500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", preferencesUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetPreferences400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	stored, err := s.preferences.Merge(ctx, map[string]string(*request.Body))
	if err != nil {
		if errors.Is(err, preferences.ErrInvalid) {
			return gen.SetPreferences400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("store preferences", "error", err)
		return gen.SetPreferences500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store preferences; see the server log"),
		}, nil
	}
	return gen.SetPreferences200JSONResponse(stored), nil
}
