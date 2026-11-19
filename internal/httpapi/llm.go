package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/localllm"
	"github.com/ozerozdas/bastion/internal/reports"
)

// llmUnavailable is the detail for the local-model endpoints when serve did
// not wire a service (some tests build a Server without one).
const llmUnavailable = "the local model is not configured; start bastion with its data directory"

// GetLLMSettings implements gen.StrictServerInterface. There is no credential
// to hide: the endpoint is loopback-only by construction.
func (s *Server) GetLLMSettings(_ context.Context, _ gen.GetLLMSettingsRequestObject) (gen.GetLLMSettingsResponseObject, error) {
	if s.llm == nil {
		return gen.GetLLMSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", llmUnavailable),
		}, nil
	}
	return gen.GetLLMSettings200JSONResponse(llmSettingsResponse(s.llm)), nil
}

// SetLLMSettings implements gen.StrictServerInterface. The body merges into
// the stored settings: fields it omits are left untouched.
func (s *Server) SetLLMSettings(_ context.Context, request gen.SetLLMSettingsRequestObject) (gen.SetLLMSettingsResponseObject, error) {
	if s.llm == nil {
		return gen.SetLLMSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", llmUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetLLMSettings400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	body := request.Body
	if _, err := s.llm.Update(localllm.UpdateInput{
		Enabled:  body.Enabled,
		Endpoint: body.Endpoint,
		Model:    body.Model,
	}); err != nil {
		if errors.Is(err, localllm.ErrInvalid) {
			return gen.SetLLMSettings422ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error()),
			), nil
		}
		s.log.Error("store local model settings", "error", err)
		return gen.SetLLMSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the local model settings; see the server log"),
		}, nil
	}
	return gen.SetLLMSettings200JSONResponse(llmSettingsResponse(s.llm)), nil
}

// ListLLMModels implements gen.StrictServerInterface. It asks the endpoint for
// its model list so the settings form can offer the names. The endpoint is
// optional and defaults to the saved one; either way it goes through the same
// loopback validation as a save, and the request is made here because the
// UI's CSP forbids the browser from calling the model server directly.
func (s *Server) ListLLMModels(ctx context.Context, request gen.ListLLMModelsRequestObject) (gen.ListLLMModelsResponseObject, error) {
	if s.llm == nil {
		return gen.ListLLMModels500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", llmUnavailable),
		}, nil
	}

	endpoint := ""
	if request.Params.Endpoint != nil {
		endpoint = strings.TrimSpace(*request.Params.Endpoint)
	}
	models, err := s.llm.Models(ctx, endpoint)
	if err != nil {
		if errors.Is(err, localllm.ErrInvalid) {
			return gen.ListLLMModels400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		// The transport error and the endpoint's status stay in the log.
		s.log.Warn("list local models", "error", err)
		return gen.ListLLMModels502ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadGateway, "Bad Gateway",
				"the local model endpoint did not answer; check the endpoint and the server log"),
		), nil
	}
	return gen.ListLLMModels200JSONResponse(gen.LLMModels{Models: models}), nil
}

// ExplainFinding implements gen.StrictServerInterface. It reads the finding// from the database (never from the request body), sends it to the local model
// and returns the answer. Nothing is written: the endpoint is read-only.
func (s *Server) ExplainFinding(ctx context.Context, request gen.ExplainFindingRequestObject) (gen.ExplainFindingResponseObject, error) {
	if s.llm == nil {
		return gen.ExplainFinding500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", llmUnavailable),
		}, nil
	}
	if s.reports == nil {
		return gen.ExplainFinding500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}
	if request.AssetId <= 0 || request.Fingerprint == "" {
		return gen.ExplainFinding400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "an asset id and a fingerprint are required"),
		), nil
	}

	finding, found, err := s.findingForExplain(ctx, request.AssetId, string(request.Fingerprint))
	if err != nil {
		s.log.Error("read finding for explanation", "asset", request.AssetId, "error", err)
		return gen.ExplainFinding500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the finding; see the server log"),
		}, nil
	}
	if !found {
		return gen.ExplainFinding404ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusNotFound, "Not Found", fmt.Sprintf(
				"asset %d has no finding with that fingerprint", request.AssetId)),
		), nil
	}

	result, err := s.llm.Explain(ctx, localllm.ExplainInput{
		Title:          finding.Title,
		RuleID:         finding.RuleID,
		PackageName:    finding.PackageName,
		PackageVersion: finding.PackageVersion,
		FixedVersion:   finding.FixedVersion,
		Location:       finding.Location,
		Severity:       finding.Severity,
		Description:    finding.Description,
		EPSS:           epssForExplain(finding),
	})
	if err != nil {
		switch {
		case errors.Is(err, localllm.ErrDisabled),
			errors.Is(err, localllm.ErrNotConfigured),
			errors.Is(err, localllm.ErrInvalid):
			return gen.ExplainFinding400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		default:
			// The transport error and the endpoint's status stay in the log.
			s.log.Warn("explain finding", "asset", request.AssetId, "error", err)
			return gen.ExplainFinding502ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadGateway, "Bad Gateway",
					"the local model did not answer; check its settings and the server log"),
			), nil
		}
	}
	return gen.ExplainFinding200JSONResponse(gen.ExplainFindingResponse{
		Text:  result.Text,
		Model: result.Model,
	}), nil
}

// findingForExplain looks one finding up among the latest findings of the
// asset. The latest list is what the drawer renders, so the lookup matches
// exactly the row the user clicked; an archived asset or a fixed finding is
// not found.
func (s *Server) findingForExplain(ctx context.Context, assetID int64, fingerprint string) (reports.Finding, bool, error) {
	findings, err := s.reports.Findings(ctx, reports.Filter{AssetID: assetID, Fingerprint: fingerprint})
	if err != nil {
		return reports.Finding{}, false, err
	}
	if len(findings) == 0 {
		return reports.Finding{}, false, nil
	}
	return findings[0], true, nil
}

// epssForExplain converts the report read model's EPSS score to the prompt
// type. A missing score stays nil, so the prompt does not claim one.
func epssForExplain(finding reports.Finding) *localllm.EPSS {
	if finding.EPSS == nil {
		return nil
	}
	return &localllm.EPSS{
		Score:      finding.EPSS.Score,
		Percentile: finding.EPSS.Percentile,
	}
}

// llmSettingsResponse maps the domain settings onto the API shape.
func llmSettingsResponse(service *localllm.Service) gen.LLMSettings {
	settings := service.Settings()
	return gen.LLMSettings{
		Enabled:  settings.Enabled,
		Endpoint: settings.Endpoint,
		Model:    settings.Model,
	}
}
