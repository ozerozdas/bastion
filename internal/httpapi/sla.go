package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// GetSLASettings implements gen.StrictServerInterface.
func (s *Server) GetSLASettings(ctx context.Context, _ gen.GetSLASettingsRequestObject) (gen.GetSLASettingsResponseObject, error) {
	if s.reports == nil {
		return gen.GetSLASettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	thresholds, err := s.reports.SLAThresholds(ctx)
	if err != nil {
		s.log.Error("read sla thresholds", "error", err)
		return gen.GetSLASettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the SLA thresholds; see the server log"),
		}, nil
	}
	return gen.GetSLASettings200JSONResponse(slaThresholdsResponse(thresholds)), nil
}

// SetSLASettings implements gen.StrictServerInterface. Every severity is
// required, so an explicit zero is a 400 like any other out-of-range value.
func (s *Server) SetSLASettings(ctx context.Context, request gen.SetSLASettingsRequestObject) (gen.SetSLASettingsResponseObject, error) {
	if s.reports == nil {
		return gen.SetSLASettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetSLASettings400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	stored, err := s.reports.SetSLAThresholds(ctx, reports.SLAThresholds{
		Critical: request.Body.Critical,
		High:     request.Body.High,
		Medium:   request.Body.Medium,
		Low:      request.Body.Low,
	})
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.SetSLASettings400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("store sla thresholds", "error", err)
		return gen.SetSLASettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the SLA thresholds; see the server log"),
		}, nil
	}
	return gen.SetSLASettings200JSONResponse(slaThresholdsResponse(stored)), nil
}

// GetReportSLA implements gen.StrictServerInterface.
func (s *Server) GetReportSLA(ctx context.Context, request gen.GetReportSLARequestObject) (gen.GetReportSLAResponseObject, error) {
	if s.reports == nil {
		return gen.GetReportSLA500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	assetID, ok := reportAssetID(request.Params.AssetId)
	if !ok {
		return gen.GetReportSLA400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "asset_id must be a positive integer"),
		), nil
	}
	days := reports.DefaultSLAWindowDays
	if request.Params.Days != nil {
		days = *request.Params.Days
	}
	report, err := s.reports.SLA(ctx, assetID, days)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.GetReportSLA400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("sla report", "asset", assetID, "error", err)
		return gen.GetReportSLA500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the SLA report; see the server log"),
		}, nil
	}

	out := gen.SLAReport{
		Thresholds:       slaThresholdsResponse(report.Thresholds),
		Overdue:          make([]gen.SLAOverdueFinding, 0, len(report.Overdue)),
		OpenCount:        report.OpenCount,
		OverdueCount:     report.OverdueCount,
		OverdueTruncated: report.OverdueTruncated,
		FixedInWindow:    report.FixedInWindow,
	}
	for _, item := range report.Overdue {
		out.Overdue = append(out.Overdue, gen.SLAOverdueFinding{
			Finding:       findingResponse(item.Finding),
			FirstSeen:     item.FirstSeen,
			AgeDays:       item.AgeDays,
			ThresholdDays: item.ThresholdDays,
			OverdueDays:   item.OverdueDays,
		})
	}
	if report.MeanTimeToFixDays != nil {
		mean := *report.MeanTimeToFixDays
		out.MeanTimeToFixDays = &mean
	}
	return gen.GetReportSLA200JSONResponse(out), nil
}

// slaThresholdsResponse maps the domain thresholds onto the API shape.
func slaThresholdsResponse(thresholds reports.SLAThresholds) gen.SLAThresholds {
	return gen.SLAThresholds{
		Critical: thresholds.Critical,
		High:     thresholds.High,
		Medium:   thresholds.Medium,
		Low:      thresholds.Low,
	}
}
