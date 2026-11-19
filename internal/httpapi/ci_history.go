package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// GetReportCIHistory implements gen.StrictServerInterface.
func (s *Server) GetReportCIHistory(ctx context.Context, request gen.GetReportCIHistoryRequestObject) (gen.GetReportCIHistoryResponseObject, error) {
	if s.reports == nil {
		return gen.GetReportCIHistory500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	assetID, ok := reportAssetID(request.Params.AssetId)
	if !ok {
		return gen.GetReportCIHistory400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "asset_id must be a positive integer"),
		), nil
	}
	limit := reports.DefaultCIHistoryLimit
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}
	report, err := s.reports.CIHistory(ctx, assetID, limit)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.GetReportCIHistory400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("report ci history", "asset", assetID, "error", err)
		return gen.GetReportCIHistory500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the CI history; see the server log"),
		}, nil
	}

	out := gen.CIHistoryReport{Runs: make([]gen.CIRun, 0, len(report.Runs))}
	for _, run := range report.Runs {
		scanners := make([]gen.CIScannerRun, 0, len(run.Scanners))
		for _, scanner := range run.Scanners {
			scanners = append(scanners, gen.CIScannerRun{
				Scanner: scanner.Scanner,
				Status:  gen.ScanStatus(scanner.Status),
			})
		}
		out.Runs = append(out.Runs, gen.CIRun{
			ScanId:      run.ScanID,
			AssetId:     run.AssetID,
			DisplayName: run.DisplayName,
			Trigger:     gen.CIRunTrigger(run.Trigger),
			Status:      gen.ScanStatus(run.Status),
			StartedAt:   run.StartedAt,
			FinishedAt:  run.FinishedAt,
			DurationMs:  run.DurationMS,
			Counts:      severityTotalsResponse(run.Counts),
			Scanners:    scanners,
		})
	}
	return gen.GetReportCIHistory200JSONResponse(out), nil
}
