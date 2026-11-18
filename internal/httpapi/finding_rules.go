package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// ListFindingRules implements gen.StrictServerInterface.
func (s *Server) ListFindingRules(ctx context.Context, _ gen.ListFindingRulesRequestObject) (gen.ListFindingRulesResponseObject, error) {
	if s.assets == nil {
		return gen.ListFindingRules500ApplicationProblemPlusJSONResponse(unconfigured(assetsUnavailable)), nil
	}
	rules, err := s.assets.FindingRules(ctx)
	if err != nil {
		s.log.Error("list finding rules", "error", err)
		_, problem := assetProblem(err)
		return gen.ListFindingRules500ApplicationProblemPlusJSONResponse(problem), nil
	}
	out := make([]gen.FindingRule, 0, len(rules))
	for _, rule := range rules {
		item := gen.FindingRule{
			Id:          rule.ID,
			AssetId:     rule.AssetID,
			RuleId:      stringPointer(rule.RuleID),
			PackageName: stringPointer(rule.PackageName),
			PathGlob:    stringPointer(rule.PathGlob),
			State:       gen.FindingState(rule.State),
			Reason:      rule.Reason,
			ExpiresAt:   stringPointer(rule.ExpiresAt),
			Status:      gen.FindingRuleStatus(rule.Status),
			CreatedBy:   gen.FindingDecider(rule.CreatedBy),
			CreatedAt:   rule.CreatedAt,
			Matched:     rule.Matched,
		}
		if rule.FindingType != "" {
			kind := gen.FindingType(rule.FindingType)
			item.FindingType = &kind
		}
		out = append(out, item)
	}
	return gen.ListFindingRules200JSONResponse(gen.FindingRuleList{Rules: out}), nil
}

// CreateFindingRule implements gen.StrictServerInterface.
func (s *Server) CreateFindingRule(ctx context.Context, request gen.CreateFindingRuleRequestObject) (gen.CreateFindingRuleResponseObject, error) {
	if s.assets == nil {
		return gen.CreateFindingRule500ApplicationProblemPlusJSONResponse(unconfigured(assetsUnavailable)), nil
	}
	if request.Body == nil {
		return gen.CreateFindingRule400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required")), nil
	}
	body := request.Body
	input := assets.FindingRuleInput{
		AssetID:     body.AssetId,
		RuleID:      stringValue(body.RuleId),
		PackageName: stringValue(body.PackageName),
		PathGlob:    stringValue(body.PathGlob),
		State:       string(body.State),
		Reason:      body.Reason,
		ExpiresAt:   stringValue(body.ExpiresAt),
	}
	if body.FindingType != nil {
		input.FindingType = string(*body.FindingType)
	}
	if _, err := s.assets.CreateFindingRule(ctx, input); err != nil {
		s.log.Error("create finding rule", "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.CreateFindingRule400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.CreateFindingRule404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.CreateFindingRule500ApplicationProblemPlusJSONResponse(problem), nil
		}
	}
	return gen.CreateFindingRule204Response{}, nil
}

// ApproveFindingRule implements gen.StrictServerInterface.
func (s *Server) ApproveFindingRule(ctx context.Context, request gen.ApproveFindingRuleRequestObject) (gen.ApproveFindingRuleResponseObject, error) {
	if s.assets == nil {
		return gen.ApproveFindingRule500ApplicationProblemPlusJSONResponse(unconfigured(assetsUnavailable)), nil
	}
	if err := s.assets.ApproveFindingRule(ctx, request.Id); err != nil {
		s.log.Error("approve finding rule", "rule", request.Id, "error", err)
		status, problem := assetProblem(err)
		if status == http.StatusNotFound {
			return gen.ApproveFindingRule404ApplicationProblemPlusJSONResponse(problem), nil
		}
		return gen.ApproveFindingRule500ApplicationProblemPlusJSONResponse(problem), nil
	}
	return gen.ApproveFindingRule204Response{}, nil
}

// DeleteFindingRule implements gen.StrictServerInterface.
func (s *Server) DeleteFindingRule(ctx context.Context, request gen.DeleteFindingRuleRequestObject) (gen.DeleteFindingRuleResponseObject, error) {
	if s.assets == nil {
		return gen.DeleteFindingRule500ApplicationProblemPlusJSONResponse(unconfigured(assetsUnavailable)), nil
	}
	if err := s.assets.DeleteFindingRule(ctx, request.Id); err != nil {
		s.log.Error("delete finding rule", "rule", request.Id, "error", err)
		status, problem := assetProblem(err)
		if status == http.StatusNotFound {
			return gen.DeleteFindingRule404ApplicationProblemPlusJSONResponse(problem), nil
		}
		return gen.DeleteFindingRule500ApplicationProblemPlusJSONResponse(problem), nil
	}
	return gen.DeleteFindingRule204Response{}, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
