package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/fixplan"
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

// GetAssetFixPlan implements gen.StrictServerInterface.
func (s *Server) GetAssetFixPlan(ctx context.Context, request gen.GetAssetFixPlanRequestObject) (gen.GetAssetFixPlanResponseObject, error) {
	if s.reports == nil {
		return gen.GetAssetFixPlan500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	plan, err := s.reports.FixPlan(ctx, int64(request.Id))
	if err != nil {
		switch {
		case errors.Is(err, reports.ErrInvalid):
			return gen.GetAssetFixPlan400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		case errors.Is(err, reports.ErrNotFound):
			return gen.GetAssetFixPlan404ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusNotFound, "Not Found", err.Error()),
			), nil
		}
		s.log.Error("fix plan", "asset", request.Id, "error", err)
		return gen.GetAssetFixPlan500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the fix plan; see the server log"),
		}, nil
	}
	return gen.GetAssetFixPlan200JSONResponse(fixPlanResponse(plan)), nil
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
	if finding.EPSS != nil {
		out.Epss = &gen.EPSSScore{
			Score:      finding.EPSS.Score,
			Percentile: finding.EPSS.Percentile,
		}
	}
	if out.References == nil {
		out.References = []string{}
	}
	if out.Scanners == nil {
		out.Scanners = []string{}
	}
	return out
}

// fixPlanResponse maps a domain fix plan onto the API shape. Both lists are
// always JSON arrays, never null.
func fixPlanResponse(plan fixplan.Plan) gen.FixPlan {
	steps := make([]gen.FixPlanStep, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		installed := step.InstalledVersions
		if installed == nil {
			installed = []string{}
		}
		ids := step.FindingIDs
		if ids == nil {
			ids = []int64{}
		}
		steps = append(steps, gen.FixPlanStep{
			Ecosystem:         step.Ecosystem,
			Package:           step.Package,
			InstalledVersions: installed,
			TargetVersion:     step.TargetVersion,
			Approximate:       step.Approximate,
			FindingCount:      step.FindingCount,
			SeverityCounts:    fixPlanSeverityTotals(step.SeverityCounts),
			FindingIds:        ids,
			MaxEpss:           epssScorePointer(step.MaxEPSS),
			Score:             step.Score,
			Factors:           fixPlanFactors(step.Factors),
		})
	}

	noFix := make([]gen.FixPlanNoFix, 0, len(plan.NoFix))
	for _, group := range plan.NoFix {
		ids := group.FindingIDs
		if ids == nil {
			ids = []int64{}
		}
		noFix = append(noFix, gen.FixPlanNoFix{
			Ecosystem:      group.Ecosystem,
			Package:        group.Package,
			FindingCount:   group.FindingCount,
			SeverityCounts: fixPlanSeverityTotals(group.SeverityCounts),
			FindingIds:     ids,
		})
	}

	return gen.FixPlan{Steps: steps, NoFix: noFix}
}

// epssScorePointer maps an optional domain score onto the API shape. Nil stays
// absent, which is what a finding without a score (feed off or CVE unscored)
// reports.
func epssScorePointer(score *epss.Score) *gen.EPSSScore {
	if score == nil {
		return nil
	}
	return &gen.EPSSScore{Score: score.Score, Percentile: score.Percentile}
}

// fixPlanSeverityTotals maps one step's severity counts onto the API shape.
func fixPlanSeverityTotals(counts fixplan.SeverityCounts) gen.SeverityTotals {
	return gen.SeverityTotals{
		Critical: counts.Critical,
		High:     counts.High,
		Medium:   counts.Medium,
		Low:      counts.Low,
		Unknown:  counts.Unknown,
	}
}

// fixPlanFactors maps a step's score factors onto the API shape. The list is
// always an array, never null.
func fixPlanFactors(factors []fixplan.Factor) []gen.FixPlanFactor {
	out := make([]gen.FixPlanFactor, 0, len(factors))
	for _, factor := range factors {
		out = append(out, gen.FixPlanFactor{
			Name:   gen.FixPlanFactorName(factor.Name),
			Value:  factor.Value,
			Detail: factor.Detail,
		})
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
