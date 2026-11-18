package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// The handlers in this file stay thin (PROJECT_SPEC.md §9.2): decode, call the
// assets service (or the reports service for scan findings), map domain errors
// to problem+json. Validation lives in the service.

// assetsUnavailable is the detail for endpoints that need the service but were
// built without one.
const assetsUnavailable = "assets are not configured; start bastion serve with its database"

// ListAssets implements gen.StrictServerInterface.
func (s *Server) ListAssets(ctx context.Context, _ gen.ListAssetsRequestObject) (gen.ListAssetsResponseObject, error) {
	if s.assets == nil {
		return gen.ListAssets500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	list, err := s.assets.List(ctx)
	if err != nil {
		s.log.Error("list assets", "error", err)
		return gen.ListAssets500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the assets; see the server log"),
		}, nil
	}

	out := make([]gen.Asset, 0, len(list))
	for _, asset := range list {
		out = append(out, assetResponse(asset))
	}
	return gen.ListAssets200JSONResponse{Assets: out}, nil
}

// CreateAsset implements gen.StrictServerInterface.
func (s *Server) CreateAsset(ctx context.Context, request gen.CreateAssetRequestObject) (gen.CreateAssetResponseObject, error) {
	if s.assets == nil {
		return gen.CreateAsset500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.CreateAsset400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	in := assets.CreateInput{
		Kind: string(request.Body.Kind),
		Ref:  request.Body.Ref,
	}
	if request.Body.ConnectionId != nil {
		in.ConnectionID = *request.Body.ConnectionId
	}
	if request.Body.Tag != nil {
		in.Tag = *request.Body.Tag
	}

	asset, err := s.assets.Create(ctx, in)
	if err != nil {
		s.log.Error("create asset", "kind", in.Kind, "ref", Redact(in.Ref), "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.CreateAsset400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.CreateAsset404ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusConflict:
			return gen.CreateAsset409ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusBadGateway:
			return gen.CreateAsset502ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.CreateAsset500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.CreateAsset201JSONResponse(assetResponse(asset)), nil
}

// DeleteAsset implements gen.StrictServerInterface.
func (s *Server) DeleteAsset(ctx context.Context, request gen.DeleteAssetRequestObject) (gen.DeleteAssetResponseObject, error) {
	if s.assets == nil {
		return gen.DeleteAsset500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if err := s.assets.Archive(ctx, int64(request.Id)); err != nil {
		s.log.Error("archive asset", "id", request.Id, "error", err)
		status, problem := assetProblem(err)
		if status == http.StatusNotFound {
			return gen.DeleteAsset404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
		return gen.DeleteAsset500ApplicationProblemPlusJSONResponse{Body: problem}, nil
	}
	return gen.DeleteAsset204Response{}, nil
}

// SetAssetLink implements gen.StrictServerInterface. {id} is the image; the
// body names the repository. A manual link replaces any previous one.
func (s *Server) SetAssetLink(ctx context.Context, request gen.SetAssetLinkRequestObject) (gen.SetAssetLinkResponseObject, error) {
	if s.assets == nil {
		return gen.SetAssetLink500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.SetAssetLink400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}
	asset, err := s.assets.SetLink(ctx, int64(request.Id), request.Body.RepoAssetId)
	if err != nil {
		s.log.Error("set asset link", "image", request.Id, "repo", request.Body.RepoAssetId, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.SetAssetLink400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.SetAssetLink404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.SetAssetLink500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.SetAssetLink200JSONResponse(assetResponse(asset)), nil
}

// SetAssetSchedule implements gen.StrictServerInterface. The schedule decides
// whether `bastion serve` queues the asset on its own; off is the default.
func (s *Server) SetAssetSchedule(ctx context.Context, request gen.SetAssetScheduleRequestObject) (gen.SetAssetScheduleResponseObject, error) {
	if s.assets == nil {
		return gen.SetAssetSchedule500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.SetAssetSchedule400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}
	asset, err := s.assets.SetSchedule(ctx, int64(request.Id), string(request.Body.Schedule))
	if err != nil {
		s.log.Error("set asset schedule", "id", request.Id, "schedule", request.Body.Schedule, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.SetAssetSchedule400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.SetAssetSchedule404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.SetAssetSchedule500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.SetAssetSchedule200JSONResponse(assetResponse(asset)), nil
}

// ClearAssetLink implements gen.StrictServerInterface. {id} is the image; the
// link is removed whichever source created it.
func (s *Server) ClearAssetLink(ctx context.Context, request gen.ClearAssetLinkRequestObject) (gen.ClearAssetLinkResponseObject, error) {
	if s.assets == nil {
		return gen.ClearAssetLink500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if err := s.assets.ClearLink(ctx, int64(request.Id)); err != nil {
		s.log.Error("clear asset link", "image", request.Id, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.ClearAssetLink400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.ClearAssetLink404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		default:
			return gen.ClearAssetLink500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.ClearAssetLink204Response{}, nil
}

// ListScans implements gen.StrictServerInterface.
func (s *Server) ListScans(ctx context.Context, request gen.ListScansRequestObject) (gen.ListScansResponseObject, error) {
	if s.assets == nil {
		return gen.ListScans500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}

	var assetID int64
	if request.Params.AssetId != nil {
		assetID = int64(*request.Params.AssetId)
	}
	limit := assets.DefaultScanLimit
	if request.Params.Limit != nil {
		limit = int(*request.Params.Limit)
	}
	offset := 0
	if request.Params.Offset != nil {
		offset = int(*request.Params.Offset)
	}

	by := assets.ScanSort{}
	if request.Params.Sort != nil {
		by.Column = string(*request.Params.Sort)
	}
	if request.Params.Order != nil {
		by.Order = string(*request.Params.Order)
	}

	page, err := s.assets.Scans(ctx, assetID, limit, offset, by)
	if err != nil {
		if errors.Is(err, assets.ErrInvalid) {
			return gen.ListScans400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("list scans", "error", err)
		return gen.ListScans500ApplicationProblemPlusJSONResponse{Body: unconfigured(
			"could not read the scans; see the server log")}, nil
	}

	out := make([]gen.Scan, 0, len(page.Scans))
	for _, scan := range page.Scans {
		out = append(out, scanResponse(scan, false))
	}
	return gen.ListScans200JSONResponse{
		Scans:  out,
		Total:  page.Total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// CreateScans implements gen.StrictServerInterface.
func (s *Server) CreateScans(ctx context.Context, request gen.CreateScansRequestObject) (gen.CreateScansResponseObject, error) {
	if s.assets == nil {
		return gen.CreateScans500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.CreateScans400ApplicationProblemPlusJSONResponse{Body: newProblem(
			http.StatusBadRequest, "Bad Request", "the request body is required")}, nil
	}

	queued, err := s.assets.Enqueue(ctx, request.Body.AssetIds)
	if err != nil {
		s.log.Error("queue scans", "assets", request.Body.AssetIds, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.CreateScans400ApplicationProblemPlusJSONResponse{Body: problem}, nil
		case http.StatusNotFound:
			return gen.CreateScans404ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusConflict:
			return gen.CreateScans409ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.CreateScans500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}

	out := make([]gen.QueuedScan, 0, len(queued))
	for _, scan := range queued {
		out = append(out, gen.QueuedScan{ScanId: scan.ScanID, AssetId: scan.AssetID})
	}
	return gen.CreateScans202JSONResponse{Scans: out}, nil
}

// GetScan implements gen.StrictServerInterface.
func (s *Server) GetScan(ctx context.Context, request gen.GetScanRequestObject) (gen.GetScanResponseObject, error) {
	if s.assets == nil {
		return gen.GetScan500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	scan, err := s.assets.Scan(ctx, int64(request.Id))
	if err != nil {
		s.log.Error("get scan", "id", request.Id, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusNotFound:
			return gen.GetScan404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		case http.StatusBadRequest:
			return gen.GetScan404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		default:
			return gen.GetScan500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.GetScan200JSONResponse(scanResponse(scan, true)), nil
}

// CancelScan implements gen.StrictServerInterface.
func (s *Server) CancelScan(ctx context.Context, request gen.CancelScanRequestObject) (gen.CancelScanResponseObject, error) {
	if s.assets == nil {
		return gen.CancelScan500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	scan, err := s.assets.Cancel(ctx, int64(request.Id))
	if err != nil {
		s.log.Error("cancel scan", "id", request.Id, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusNotFound:
			return gen.CancelScan404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		case http.StatusConflict:
			return gen.CancelScan409ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.CancelScan500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.CancelScan200JSONResponse(scanResponse(scan, false)), nil
}

// ListScanFindings implements gen.StrictServerInterface. The findings read
// model belongs to the reports service; the scan itself is checked here so an
// unknown id is a 404 rather than an empty list.
func (s *Server) ListScanFindings(ctx context.Context, request gen.ListScanFindingsRequestObject) (gen.ListScanFindingsResponseObject, error) {
	if s.reports == nil || s.assets == nil {
		return gen.ListScanFindings500ApplicationProblemPlusJSONResponse{Body: unconfigured(reportsUnavailable)}, nil
	}
	// The scan must exist; Scan also validates the id.
	if _, err := s.assets.Scan(ctx, int64(request.Id)); err != nil {
		s.log.Error("list scan findings", "id", request.Id, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusNotFound, http.StatusBadRequest:
			return gen.ListScanFindings404ApplicationProblemPlusJSONResponse{Body: problem}, nil
		default:
			return gen.ListScanFindings500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}

	filter := reports.ScanFilter{}
	if request.Params.Severity != nil {
		filter.Severity = string(*request.Params.Severity)
	}
	if request.Params.Type != nil {
		filter.Type = string(*request.Params.Type)
	}
	if request.Params.Status != nil {
		filter.Status = string(*request.Params.Status)
	}

	offset := 0
	if request.Params.Offset != nil {
		offset = int(*request.Params.Offset)
	}

	page, err := s.reports.ScanFindingsPage(ctx, int64(request.Id), filter, offset)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.ListScanFindings400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("list scan findings", "id", request.Id, "error", err)
		return gen.ListScanFindings500ApplicationProblemPlusJSONResponse{Body: unconfigured(
			"could not read the findings; see the server log")}, nil
	}

	out := make([]gen.Finding, 0, len(page.Findings))
	for _, finding := range page.Findings {
		out = append(out, findingResponse(finding))
	}
	return gen.ListScanFindings200JSONResponse{
		Findings:      out,
		Groups:        make([]gen.FindingGroup, 0),
		Total:         page.Total,
		TotalFindings: page.Total,
		Limit:         0,
		Offset:        offset,
	}, nil
}

// GetScanDiff implements gen.StrictServerInterface. The diff itself belongs to
// the reports service (it reads findings through ScanFindings); the handler
// only maps the result onto the generated types.
func (s *Server) GetScanDiff(ctx context.Context, request gen.GetScanDiffRequestObject) (gen.GetScanDiffResponseObject, error) {
	if s.reports == nil {
		return gen.GetScanDiff500ApplicationProblemPlusJSONResponse{Body: unconfigured(reportsUnavailable)}, nil
	}

	// 0 means "the default baseline" to the service, so an explicit
	// ?against=0 must not silently fall through to it.
	var against int64
	if request.Params.Against != nil {
		against = *request.Params.Against
		if against < 1 {
			return gen.GetScanDiff400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", "against must be a scan id (1 or greater)")), nil
		}
	}

	diff, err := s.reports.ScanDiff(ctx, int64(request.Id), against)
	if err != nil {
		switch {
		case errors.Is(err, reports.ErrNotFound):
			return gen.GetScanDiff404ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusNotFound, "Not Found", err.Error())), nil
		case errors.Is(err, reports.ErrInvalid):
			return gen.GetScanDiff400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error())), nil
		case errors.Is(err, reports.ErrConflict):
			return gen.GetScanDiff409ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusConflict, "Conflict", err.Error())), nil
		default:
			s.log.Error("scan diff", "id", request.Id, "against", against, "error", err)
			return gen.GetScanDiff500ApplicationProblemPlusJSONResponse{Body: unconfigured(
				"could not diff the scans; see the server log")}, nil
		}
	}
	return gen.GetScanDiff200JSONResponse(scanDiffResponse(diff)), nil
}

// SetFindingStates implements gen.StrictServerInterface. One decision applies
// to many fingerprints of one asset; an unknown fingerprint rejects the whole
// batch, and the problem names the culprits in its `fingerprints` member.
func (s *Server) SetFindingStates(ctx context.Context, request gen.SetFindingStatesRequestObject) (gen.SetFindingStatesResponseObject, error) {
	if s.assets == nil {
		return gen.SetFindingStates500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.SetFindingStates400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	err := s.assets.SetFindingStates(ctx, assets.BulkFindingStateInput{
		AssetID:      request.Body.AssetId,
		Fingerprints: request.Body.Fingerprints,
		State:        string(request.Body.State),
		Reason:       request.Body.Reason,
		ExpiresAt:    expiresAtValue(request.Body.ExpiresAt),
	})
	if err != nil {
		s.log.Error("set finding states", "asset", request.Body.AssetId, "error", err)
		var unknown *assets.UnknownFingerprintsError
		if errors.As(err, &unknown) {
			problem := newProblem(http.StatusNotFound, "Not Found", fmt.Sprintf(
				"asset %d has no finding for %d of the fingerprints; nothing was written",
				unknown.AssetID, len(unknown.Fingerprints)))
			problem.Fingerprints = &unknown.Fingerprints
			return gen.SetFindingStates404ApplicationProblemPlusJSONResponse(problem), nil
		}
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.SetFindingStates400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.SetFindingStates404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.SetFindingStates500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.SetFindingStates204Response{}, nil
}

// SetFindingState implements gen.StrictServerInterface.
func (s *Server) SetFindingState(ctx context.Context, request gen.SetFindingStateRequestObject) (gen.SetFindingStateResponseObject, error) {
	if s.assets == nil {
		return gen.SetFindingState500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	if request.Body == nil {
		return gen.SetFindingState400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	err := s.assets.SetFindingState(ctx, assets.FindingStateInput{
		AssetID:     request.Body.AssetId,
		Fingerprint: request.Fingerprint,
		State:       string(request.Body.State),
		Reason:      request.Body.Reason,
		ExpiresAt:   expiresAtValue(request.Body.ExpiresAt),
	})
	if err != nil {
		s.log.Error("set finding state", "asset", request.Body.AssetId, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.SetFindingState400ApplicationProblemPlusJSONResponse(problem), nil
		case http.StatusNotFound:
			return gen.SetFindingState404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.SetFindingState500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.SetFindingState204Response{}, nil
}

// ClearFindingState implements gen.StrictServerInterface. Clearing is a DELETE
// with asset_id in the query because the decision key is
// (asset_id, fingerprint).
func (s *Server) ClearFindingState(ctx context.Context, request gen.ClearFindingStateRequestObject) (gen.ClearFindingStateResponseObject, error) {
	if s.assets == nil {
		return gen.ClearFindingState500ApplicationProblemPlusJSONResponse{Body: unconfigured(assetsUnavailable)}, nil
	}
	err := s.assets.ClearFindingState(ctx, int64(request.Params.AssetId), request.Fingerprint)
	if err != nil {
		s.log.Error("clear finding state", "asset", request.Params.AssetId, "error", err)
		status, problem := assetProblem(err)
		switch status {
		case http.StatusBadRequest:
			return gen.ClearFindingState400ApplicationProblemPlusJSONResponse{
				ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{Body: problem},
			}, nil
		case http.StatusNotFound:
			return gen.ClearFindingState404ApplicationProblemPlusJSONResponse(problem), nil
		default:
			return gen.ClearFindingState500ApplicationProblemPlusJSONResponse{Body: problem}, nil
		}
	}
	return gen.ClearFindingState204Response{}, nil
}

// unconfigured builds the problem for an endpoint whose service is missing.
func unconfigured(detail string) gen.Problem {
	return newProblem(http.StatusInternalServerError, "Internal Server Error", detail)
}

// assetProblem maps assets and connections errors to problem details and an
// HTTP status. The detail is a user-facing hint; raw errors are only logged by
// the caller.
func assetProblem(err error) (int, gen.Problem) {
	status, title := http.StatusInternalServerError, "Internal Server Error"
	detail := "the request failed; see the server log"

	switch {
	case errors.Is(err, assets.ErrNotFound):
		status, title, detail = http.StatusNotFound, "Not Found", err.Error()
	case errors.Is(err, assets.ErrConflict), errors.Is(err, assets.ErrNotActive):
		status, title, detail = http.StatusConflict, "Conflict", err.Error()
	case errors.Is(err, assets.ErrInvalid):
		status, title, detail = http.StatusBadRequest, "Bad Request", err.Error()
	case errors.Is(err, assets.ErrUnavailable):
		status, title, detail = http.StatusInternalServerError, "Internal Server Error", err.Error()
	case errors.Is(err, connections.ErrNotFound):
		status, title, detail = http.StatusNotFound, "Not Found", "connection not found"
	case errors.Is(err, connections.ErrNoToken):
		status, title, detail = http.StatusConflict, "Conflict", connections.Hint(err)
	case errors.Is(err, connections.ErrInvalid), errors.Is(err, connections.ErrUnsupportedKind):
		status, title, detail = http.StatusBadRequest, "Bad Request", connections.Hint(err)
	case errors.Is(err, connections.ErrUpstream):
		status, title, detail = http.StatusBadGateway, "Bad Gateway", connections.Hint(err)
	}
	return status, newProblem(status, title, detail)
}

// assetResponse maps one domain asset onto the API shape.
func assetResponse(asset assets.Asset) gen.Asset {
	out := gen.Asset{
		Id:           asset.ID,
		Kind:         gen.AssetKind(asset.Kind),
		DisplayName:  asset.DisplayName,
		Ref:          asset.Ref,
		CreatedAt:    asset.CreatedAt,
		ScanSchedule: gen.AssetScanSchedule(asset.ScanSchedule),
		OpenCounts: gen.SeverityTotals{
			Critical: asset.OpenSeverities.Critical,
			High:     asset.OpenSeverities.High,
			Medium:   asset.OpenSeverities.Medium,
			Low:      asset.OpenSeverities.Low,
			Unknown:  asset.OpenSeverities.Unknown,
		},
	}
	if asset.ConnectionID != nil {
		id := *asset.ConnectionID
		out.ConnectionId = &id
	}
	if asset.DefaultBranch != "" {
		branch := asset.DefaultBranch
		out.DefaultBranch = &branch
	}
	if asset.ECRRegistry != "" {
		registry := asset.ECRRegistry
		out.EcrRegistry = &registry
	}
	if asset.LastScan != nil {
		last := gen.AssetLastScan{
			ScanId:     asset.LastScan.ScanID,
			Status:     gen.ScanStatus(asset.LastScan.Status),
			FinishedAt: asset.LastScan.FinishedAt,
		}
		out.LastScan = &last
	}
	if asset.LinkedRepo != nil {
		link := assetLinkResponse(*asset.LinkedRepo)
		out.LinkedRepo = &link
	}
	out.LinkedImages = make([]gen.AssetLink, 0, len(asset.LinkedImages))
	for _, image := range asset.LinkedImages {
		out.LinkedImages = append(out.LinkedImages, assetLinkResponse(image))
	}
	return out
}

// assetLinkResponse maps one link onto the API shape. Revision is only present
// when the image's labels carried one.
func assetLinkResponse(link assets.AssetLink) gen.AssetLink {
	out := gen.AssetLink{
		AssetId:     link.AssetID,
		Ref:         link.Ref,
		DisplayName: link.DisplayName,
		Source:      gen.AssetLinkSource(link.Source),
	}
	if link.Revision != "" {
		revision := link.Revision
		out.Revision = &revision
	}
	return out
}

// expiresAtValue turns the optional request field into the service's raw
// string; an absent field means no expiry.
func expiresAtValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// scanResponse maps one domain scan onto the API shape. WithRuns is false for
// the list, where scanner_runs is not loaded.
func scanResponse(scan assets.Scan, withRuns bool) gen.Scan {
	out := gen.Scan{
		Id:         scan.ID,
		AssetId:    scan.AssetID,
		Status:     gen.ScanStatus(scan.Status),
		Trigger:    gen.ScanTrigger(scan.Trigger),
		TargetRef:  stringPointer(scan.TargetRef),
		StartedAt:  scan.StartedAt,
		FinishedAt: scan.FinishedAt,
		Error:      stringPointer(scan.Error),
		Counts: gen.SeverityTotals{
			Critical: scan.Counts.Critical,
			High:     scan.Counts.High,
			Medium:   scan.Counts.Medium,
			Low:      scan.Counts.Low,
			Unknown:  scan.Counts.Unknown,
		},
	}
	if withRuns {
		runs := make([]gen.ScannerRun, 0, len(scan.ScannerRuns))
		for _, run := range scan.ScannerRuns {
			runs = append(runs, gen.ScannerRun{
				Scanner:        run.Scanner,
				ScannerVersion: stringPointer(run.ScannerVersion),
				DbVersion:      stringPointer(run.DBVersion),
				Status:         gen.ScanStatus(run.Status),
				DurationMs:     run.DurationMS,
				Error:          stringPointer(run.Error),
				Warning:        stringPointer(run.Warning),
			})
		}
		out.ScannerRuns = &runs
	}
	return out
}
