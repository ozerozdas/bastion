package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// The handlers in this file stay thin (PROJECT_SPEC.md §9.2): decode, call the
// reports service, map domain errors to problem+json. Aggregation and filter
// validation live in the service.

// reportsUnavailable is the detail for endpoints that need the service but were
// built without one.
const reportsUnavailable = "reports are not configured; start bastion with its database"

// ListFindings implements gen.StrictServerInterface.
func (s *Server) ListFindings(ctx context.Context, request gen.ListFindingsRequestObject) (gen.ListFindingsResponseObject, error) {
	if s.reports == nil {
		return gen.ListFindings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	filter := reports.Filter{}
	if request.Params.AssetId != nil {
		filter.AssetID = *request.Params.AssetId
	}
	if request.Params.Severity != nil {
		filter.Severity = string(*request.Params.Severity)
	}
	if request.Params.Type != nil {
		filter.Type = string(*request.Params.Type)
	}
	if request.Params.Status != nil {
		filter.Status = string(*request.Params.Status)
	}

	list, err := s.reports.Findings(ctx, filter)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.ListFindings400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("list findings", "error", err)
		return gen.ListFindings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the findings; see the server log"),
		}, nil
	}

	out := make([]gen.Finding, 0, len(list))
	for _, finding := range list {
		out = append(out, findingResponse(finding))
	}
	return gen.ListFindings200JSONResponse{Findings: out}, nil
}

// GetDashboard implements gen.StrictServerInterface.
func (s *Server) GetDashboard(ctx context.Context, _ gen.GetDashboardRequestObject) (gen.GetDashboardResponseObject, error) {
	if s.reports == nil {
		return gen.GetDashboard500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	dashboard, err := s.reports.Dashboard(ctx)
	if err != nil {
		s.log.Error("dashboard", "error", err)
		return gen.GetDashboard500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the dashboard; see the server log"),
		}, nil
	}
	return gen.GetDashboard200JSONResponse(dashboardResponse(dashboard)), nil
}

// findingResponse maps a domain finding onto the API shape. An unset optional
// string becomes an absent JSON field rather than "".
func findingResponse(finding reports.Finding) gen.Finding {
	out := gen.Finding{
		Id:              finding.ID,
		AssetId:         finding.AssetID,
		ScanId:          finding.ScanID,
		Fingerprint:     finding.Fingerprint,
		Type:            gen.FindingType(finding.Type),
		Severity:        gen.Severity(finding.Severity),
		Title:           finding.Title,
		RuleId:          stringPointer(finding.RuleID),
		PackageName:     stringPointer(finding.PackageName),
		PackageVersion:  stringPointer(finding.PackageVersion),
		FixedVersion:    stringPointer(finding.FixedVersion),
		Ecosystem:       stringPointer(finding.Ecosystem),
		Location:        stringPointer(finding.Location),
		Occurrences:     finding.Occurrences,
		Scanner:         finding.Scanner,
		Scanners:        finding.Scanners,
		Status:          gen.FindingStatus(finding.Status),
		State:           findingStatePointer(finding.State),
		Reason:          stringPointer(finding.Reason),
		FirstSeenScanId: finding.FirstSeenScanID,
		Description:     stringPointer(finding.Description),
		References:      finding.References,
	}
	if out.References == nil {
		out.References = []string{}
	}
	if out.Scanners == nil {
		out.Scanners = []string{}
	}
	return out
}

// scanDiffResponse maps a domain diff onto the API shape. Each group is always
// a JSON array; against_scan_id is absent when there was nothing to compare
// with.
func scanDiffResponse(diff reports.ScanDiff) gen.ScanDiff {
	return gen.ScanDiff{
		ScanId:        diff.ScanID,
		AgainstScanId: diff.AgainstScanID,
		New:           findingResponses(diff.New),
		Fixed:         findingResponses(diff.Fixed),
		Persisting:    findingResponses(diff.Persisting),
		Counts: gen.ScanDiffCounts{
			New:        severityTotalsResponse(diff.Counts.New),
			Fixed:      severityTotalsResponse(diff.Counts.Fixed),
			Persisting: severityTotalsResponse(diff.Counts.Persisting),
		},
	}
}

// findingResponses maps a group of findings, keeping [] rather than null for an
// empty group.
func findingResponses(list []reports.Finding) []gen.Finding {
	out := make([]gen.Finding, 0, len(list))
	for _, finding := range list {
		out = append(out, findingResponse(finding))
	}
	return out
}

// severityTotalsResponse maps one severity count set onto the API shape.
func severityTotalsResponse(totals reports.SeverityTotals) gen.SeverityTotals {
	return gen.SeverityTotals{
		Critical: totals.Critical,
		High:     totals.High,
		Medium:   totals.Medium,
		Low:      totals.Low,
		Unknown:  totals.Unknown,
	}
}

// dashboardResponse maps the aggregates onto the API shape.
func dashboardResponse(dashboard reports.Dashboard) gen.Dashboard {
	out := gen.Dashboard{
		TotalsBySeverity: gen.SeverityTotals{
			Critical: dashboard.TotalsBySeverity.Critical,
			High:     dashboard.TotalsBySeverity.High,
			Medium:   dashboard.TotalsBySeverity.Medium,
			Low:      dashboard.TotalsBySeverity.Low,
			Unknown:  dashboard.TotalsBySeverity.Unknown,
		},
		TotalsByType: gen.TypeTotals{
			Vulnerability: dashboard.TotalsByType.Vulnerability,
			Secret:        dashboard.TotalsByType.Secret,
			Outdated:      dashboard.TotalsByType.Outdated,
			Misconfig:     dashboard.TotalsByType.Misconfig,
			License:       dashboard.TotalsByType.License,
			Malware:       dashboard.TotalsByType.Malware,
			Sast:          dashboard.TotalsByType.SAST,
		},
		TopAssets: make([]gen.AssetRisk, 0, len(dashboard.TopAssets)),
		Trend:     make([]gen.AssetTrend, 0, len(dashboard.Trend)),
		LastScans: make([]gen.LastScan, 0, len(dashboard.LastScans)),
	}

	for _, asset := range dashboard.TopAssets {
		out.TopAssets = append(out.TopAssets, gen.AssetRisk{
			AssetId:     asset.AssetID,
			DisplayName: asset.DisplayName,
			Kind:        gen.AssetKind(asset.Kind),
			Score:       asset.Score,
			Critical:    asset.Critical,
			High:        asset.High,
			Medium:      asset.Medium,
			Low:         asset.Low,
		})
	}

	for _, trend := range dashboard.Trend {
		item := gen.AssetTrend{AssetId: trend.AssetID, Scans: make([]gen.TrendScan, 0, len(trend.Scans))}
		for _, scan := range trend.Scans {
			item.Scans = append(item.Scans, gen.TrendScan{
				ScanId:           scan.ScanID,
				FinishedAt:       scan.FinishedAt,
				CriticalHighOpen: scan.CriticalHighOpen,
			})
		}
		out.Trend = append(out.Trend, item)
	}

	for _, scan := range dashboard.LastScans {
		out.LastScans = append(out.LastScans, gen.LastScan{
			AssetId:     scan.AssetID,
			DisplayName: scan.DisplayName,
			ScanId:      scan.ScanID,
			Status:      gen.ScanStatus(scan.Status),
			FinishedAt:  scan.FinishedAt,
		})
	}

	return out
}

// stringPointer returns nil for an empty value, so the field is omitted.
func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// findingStatePointer maps an optional decision state onto the enum.
func findingStatePointer(state string) *gen.FindingState {
	if state == "" {
		return nil
	}
	mapped := gen.FindingState(state)
	return &mapped
}
