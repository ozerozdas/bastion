package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
)

// licencePolicyUnavailable is the detail for the policy endpoints when serve
// did not wire a service (some tests build a Server without one).
const licencePolicyUnavailable = "the licence policy is not configured; start bastion with its database"

// GetLicencePolicy implements gen.StrictServerInterface. Omitting asset_id
// reads the global policy.
func (s *Server) GetLicencePolicy(ctx context.Context, request gen.GetLicencePolicyRequestObject) (gen.GetLicencePolicyResponseObject, error) {
	if s.licencePolicy == nil {
		return gen.GetLicencePolicy500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", licencePolicyUnavailable),
		}, nil
	}

	policy, err := s.licencePolicy.Get(ctx, licencePolicyAssetID(request.Params.AssetId))
	if err != nil {
		return licencePolicyGetProblem(s, err)
	}
	return gen.GetLicencePolicy200JSONResponse(licencePolicyResponse(policy)), nil
}

// SetLicencePolicy implements gen.StrictServerInterface. The body replaces both
// lists of the scope in one transaction.
func (s *Server) SetLicencePolicy(ctx context.Context, request gen.SetLicencePolicyRequestObject) (gen.SetLicencePolicyResponseObject, error) {
	if s.licencePolicy == nil {
		return gen.SetLicencePolicy500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", licencePolicyUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetLicencePolicy400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	policy, err := s.licencePolicy.Replace(ctx, licencePolicyAssetID(request.Params.AssetId), licencepolicy.Policy{
		Allow: request.Body.Allow,
		Deny:  request.Body.Deny,
	})
	if err != nil {
		return licencePolicySetProblem(s, err)
	}
	return gen.SetLicencePolicy200JSONResponse(licencePolicyResponse(policy)), nil
}

// licencePolicyAssetID converts the optional query parameter to the service's
// scope pointer.
func licencePolicyAssetID(id *gen.LicencePolicyAssetIDQuery) *int64 {
	if id == nil {
		return nil
	}
	value := int64(*id)
	return &value
}

// licencePolicyResponse maps the domain policy onto the API shape, keeping []
// rather than null for an empty list.
func licencePolicyResponse(policy licencepolicy.Policy) gen.LicencePolicy {
	out := gen.LicencePolicy{
		Allow: make([]string, 0, len(policy.Allow)),
		Deny:  make([]string, 0, len(policy.Deny)),
	}
	out.Allow = append(out.Allow, policy.Allow...)
	out.Deny = append(out.Deny, policy.Deny...)
	return out
}

// licencePolicyGetProblem maps a read error onto the GET responses.
func licencePolicyGetProblem(s *Server, err error) (gen.GetLicencePolicyResponseObject, error) {
	switch {
	case errors.Is(err, licencepolicy.ErrInvalid):
		return gen.GetLicencePolicy400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
		), nil
	case errors.Is(err, licencepolicy.ErrNotFound):
		return gen.GetLicencePolicy404ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusNotFound, "Not Found", err.Error()),
		), nil
	}
	s.log.Error("read licence policy", "error", err)
	return gen.GetLicencePolicy500ApplicationProblemPlusJSONResponse{
		Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
			"could not read the licence policy; see the server log"),
	}, nil
}

// licencePolicySetProblem maps a write error onto the PUT responses.
func licencePolicySetProblem(s *Server, err error) (gen.SetLicencePolicyResponseObject, error) {
	switch {
	case errors.Is(err, licencepolicy.ErrInvalid):
		return gen.SetLicencePolicy400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
		), nil
	case errors.Is(err, licencepolicy.ErrNotFound):
		return gen.SetLicencePolicy404ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusNotFound, "Not Found", err.Error()),
		), nil
	}
	s.log.Error("store licence policy", "error", err)
	return gen.SetLicencePolicy500ApplicationProblemPlusJSONResponse{
		Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
			"could not store the licence policy; see the server log"),
	}, nil
}
