package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// GetReportAudit implements gen.StrictServerInterface.
func (s *Server) GetReportAudit(ctx context.Context, request gen.GetReportAuditRequestObject) (gen.GetReportAuditResponseObject, error) {
	if s.reports == nil {
		return gen.GetReportAudit500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	var assetID int64
	if request.Params.AssetId != nil {
		assetID = int64(*request.Params.AssetId)
	}
	report, err := s.reports.Audit(ctx, assetID)
	if err != nil {
		switch {
		case errors.Is(err, reports.ErrInvalid):
			return gen.GetReportAudit400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		case errors.Is(err, reports.ErrNotFound):
			return gen.GetReportAudit404ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusNotFound, "Not Found", err.Error()),
			), nil
		}
		s.log.Error("report audit", "asset", assetID, "error", err)
		return gen.GetReportAudit500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the audit pack; see the server log"),
		}, nil
	}

	out := gen.AuditReport{
		GeneratedAt: report.GeneratedAt,
		Summary: gen.AuditSummary{
			Critical: report.Summary.Critical,
			High:     report.Summary.High,
			Medium:   report.Summary.Medium,
			Low:      report.Summary.Low,
			Unknown:  report.Summary.Unknown,
			Total:    report.Summary.Total,
		},
		Findings:  findingResponses(report.Findings),
		FixPlan:   fixPlanResponse(report.FixPlan),
		Truncated: report.Truncated,
	}
	if report.Asset != nil {
		out.Asset = &gen.AuditAsset{
			AssetId:     report.Asset.ID,
			DisplayName: report.Asset.DisplayName,
			Kind:        gen.AssetKind(report.Asset.Kind),
		}
	}
	return gen.GetReportAudit200JSONResponse(out), nil
}
