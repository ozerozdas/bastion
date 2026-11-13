package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// The tests in this file drive the assets, scans and finding-state endpoints
// with fakes and a temporary database; nothing reaches GitHub.

// createAsset posts one asset and decodes the response.
func createAsset(t *testing.T, ts *testServer, cookie *http.Cookie, body gen.CreateAssetRequest) gen.Asset {
	t.Helper()

	resp := doJSON(t, ts, http.MethodPost, "/api/assets", body, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/assets: status = %d, want %d: %s",
			resp.StatusCode, http.StatusCreated, readBody(t, resp))
	}
	var asset gen.Asset
	if err := json.Unmarshal(readBody(t, resp), &asset); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	return asset
}

// pathAsset tracks a fresh temporary directory and returns the asset.
func pathAsset(t *testing.T, ts *testServer, cookie *http.Cookie) gen.Asset {
	t.Helper()
	return createAsset(t, ts, cookie, gen.CreateAssetRequest{
		Kind: gen.CreateAssetRequestKindPath,
		Ref:  t.TempDir(),
	})
}

// assetList decodes GET /api/assets.
func assetList(t *testing.T, ts *testServer, cookie *http.Cookie) gen.AssetList {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/api/assets", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/assets: status = %d, want %d: %s",
			resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var list gen.AssetList
	if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
		t.Fatalf("decode asset list: %v", err)
	}
	return list
}

// scanList decodes GET /api/scans.
func scanList(t *testing.T, ts *testServer, cookie *http.Cookie, query string) gen.ScanList {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/api/scans"+query, withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/scans%s: status = %d, want %d: %s",
			query, resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var list gen.ScanList
	if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
		t.Fatalf("decode scan list: %v", err)
	}
	return list
}

// decodeScan decodes one scan response.
func decodeScan(t *testing.T, resp *http.Response) gen.Scan {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan read: status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var scan gen.Scan
	if err := json.Unmarshal(readBody(t, resp), &scan); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	return scan
}

// seedSucceededScan writes one finished scan with the given findings.
func seedSucceededScan(t *testing.T, ts *testServer, assetID int64, list ...findings.Finding) int64 {
	t.Helper()

	scanID, err := store.StartScan(t.Context(), ts.db, assetID, "ui")
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if err := store.SaveScanResult(t.Context(), ts.db, scanID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: list,
	}); err != nil {
		t.Fatalf("save scan result: %v", err)
	}
	return scanID
}

// TestAssetsCRUD covers create, list, duplicate handling and archiving.
func TestAssetsCRUD(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	repo := createAsset(t, ts, cookie, gen.CreateAssetRequest{
		Kind: gen.CreateAssetRequestKindRepo,
		Ref:  "octo/hello",
	})
	if repo.Kind != gen.AssetKindRepo || repo.Ref != "octo/hello" || repo.DisplayName != "octo/hello" {
		t.Errorf("repo asset = %+v, want kind repo, ref and display name octo/hello", repo)
	}
	if repo.DefaultBranch == nil || *repo.DefaultBranch != "main" {
		t.Errorf("default_branch = %v, want main resolved through the fake GitHub", repo.DefaultBranch)
	}
	if repo.LastScan != nil {
		t.Errorf("last_scan = %+v, want absent before the first scan", repo.LastScan)
	}
	if repo.OpenCounts != (gen.SeverityTotals{}) {
		t.Errorf("open_counts = %+v, want all zero", repo.OpenCounts)
	}

	path := pathAsset(t, ts, cookie)
	if path.Kind != gen.AssetKindPath {
		t.Errorf("path asset kind = %q, want %q", path.Kind, gen.AssetKindPath)
	}

	list := assetList(t, ts, cookie)
	if len(list.Assets) != 2 {
		t.Fatalf("assets = %+v, want 2", list.Assets)
	}

	// A duplicate is a conflict, and the same repository under another case is
	// a different ref (GitHub treats names case-insensitively, the API does not).
	resp := doJSON(t, ts, http.MethodPost, "/api/assets", gen.CreateAssetRequest{
		Kind: gen.CreateAssetRequestKindRepo,
		Ref:  "octo/hello",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate asset: status = %d, want %d", resp.StatusCode, http.StatusConflict)
	}
	if problem := readProblem(t, resp); problem.Detail == nil || *problem.Detail == "" {
		t.Error("duplicate asset problem has no detail")
	}

	// Archiving removes the asset from the list but keeps the row.
	resp = doJSON(t, ts, http.MethodDelete, "/api/assets/"+itoa(path.Id), nil, withBastion(cookie))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/assets/%d: status = %d, want %d", path.Id, resp.StatusCode, http.StatusNoContent)
	}
	if list = assetList(t, ts, cookie); len(list.Assets) != 1 || list.Assets[0].Id != repo.Id {
		t.Errorf("assets after archive = %+v, want only the repo", list.Assets)
	}

	// Re-adding the archived path revives the same id, so history survives.
	revived := createAsset(t, ts, cookie, gen.CreateAssetRequest{
		Kind: gen.CreateAssetRequestKindPath,
		Ref:  path.Ref,
	})
	if revived.Id != path.Id {
		t.Errorf("revived asset id = %d, want the archived id %d", revived.Id, path.Id)
	}

	resp = doJSON(t, ts, http.MethodDelete, "/api/assets/9999", nil, withBastion(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE unknown asset: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestAssetsRejectInvalidInput covers the validation problems (§7 hints).
func TestAssetsRejectInvalidInput(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	cases := []struct {
		name string
		body gen.CreateAssetRequest
	}{
		{name: "relative path", body: gen.CreateAssetRequest{
			Kind: gen.CreateAssetRequestKindPath, Ref: "relative/dir"}},
		{name: "missing path", body: gen.CreateAssetRequest{
			Kind: gen.CreateAssetRequestKindPath, Ref: "/does/not/exist/bastion"}},
		{name: "bad repo ref", body: gen.CreateAssetRequest{
			Kind: gen.CreateAssetRequestKindRepo, Ref: "not-a-repo"}},
		{name: "unknown kind", body: gen.CreateAssetRequest{
			Kind: "image", Ref: "registry/repo"}},
		{name: "empty ref", body: gen.CreateAssetRequest{
			Kind: gen.CreateAssetRequestKindPath, Ref: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, ts, http.MethodPost, "/api/assets", tc.body, withBastion(cookie))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
			}
			if problem := readProblem(t, resp); problem.Detail == nil || *problem.Detail == "" {
				t.Error("problem has no human-readable detail")
			}
		})
	}

	// A repo whose default branch GitHub refuses is a bad gateway with the
	// GitHub hint, not a 500.
	ts.github.repoErr = errFakeGitHub
	resp := doJSON(t, ts, http.MethodPost, "/api/assets", gen.CreateAssetRequest{
		Kind: gen.CreateAssetRequestKindRepo,
		Ref:  "octo/missing",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("GitHub failure: status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	_ = readProblem(t, resp)
}

// TestQueueScanAppears covers POST /api/scans and the scan list/read.
func TestQueueScanAppears(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := pathAsset(t, ts, cookie)

	resp := doJSON(t, ts, http.MethodPost, "/api/scans", gen.CreateScansRequest{
		AssetIds: []int64{asset.Id},
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/scans: status = %d, want %d: %s", resp.StatusCode, http.StatusAccepted, readBody(t, resp))
	}
	var queued gen.ScanQueueResult
	if err := json.Unmarshal(readBody(t, resp), &queued); err != nil {
		t.Fatalf("decode queue result: %v", err)
	}
	if len(queued.Scans) != 1 || queued.Scans[0].AssetId != asset.Id || queued.Scans[0].ScanId == 0 {
		t.Fatalf("queued = %+v, want one scan of asset %d", queued.Scans, asset.Id)
	}

	list := scanList(t, ts, cookie, "?asset_id="+itoa(asset.Id))
	if len(list.Scans) != 1 || list.Scans[0].Id != queued.Scans[0].ScanId {
		t.Fatalf("scans = %+v, want the queued scan", list.Scans)
	}
	if list.Scans[0].Trigger != "ui" {
		t.Errorf("trigger = %q, want ui", list.Scans[0].Trigger)
	}
	if list.Scans[0].ScannerRuns != nil {
		t.Error("the scan list must omit scanner_runs")
	}
	if list.Scans[0].Counts != (gen.SeverityTotals{}) {
		t.Errorf("counts of a queued scan = %+v, want all zero", list.Scans[0].Counts)
	}

	scan := decodeScan(t, ts.do(t, http.MethodGet, "/api/scans/"+itoa(queued.Scans[0].ScanId), withCookie(cookie)))
	if scan.ScannerRuns == nil {
		t.Error("single scan read has no scanner_runs field")
	}

	// A bad batch is refused whole, before anything is queued.
	resp = doJSON(t, ts, http.MethodPost, "/api/scans", gen.CreateScansRequest{
		AssetIds: []int64{asset.Id, 9999},
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("batch with unknown asset: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if got := len(scanList(t, ts, cookie, "?asset_id="+itoa(asset.Id)).Scans); got != 1 {
		t.Errorf("scans after a refused batch = %d, want 1 (nothing queued)", got)
	}

	resp = doJSON(t, ts, http.MethodPost, "/api/scans", gen.CreateScansRequest{}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty batch: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// A scan of an archived asset is a conflict.
	archived := pathAsset(t, ts, cookie)
	resp = doJSON(t, ts, http.MethodDelete, "/api/assets/"+itoa(archived.Id), nil, withBastion(cookie))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("archive asset: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	resp = doJSON(t, ts, http.MethodPost, "/api/scans", gen.CreateScansRequest{
		AssetIds: []int64{archived.Id},
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("scan of archived asset: status = %d, want %d", resp.StatusCode, http.StatusConflict)
	}

	resp = ts.do(t, http.MethodGet, "/api/scans?limit=0", withCookie(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("limit=0: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestScanListSeverityCounts covers #25: each scan carries the counts of every
// finding it recorded, and a scan with no findings is all zeros.
func TestScanListSeverityCounts(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := pathAsset(t, ts, cookie)

	severity := func(fingerprint string, value findings.Severity) findings.Finding {
		return findings.Finding{
			Fingerprint: fingerprint,
			Type:        findings.TypeVulnerability,
			Severity:    value,
			Title:       "finding " + fingerprint,
			Scanner:     "trivy",
			Occurrences: 1,
		}
	}
	counted := seedSucceededScan(t, ts, asset.Id,
		severity("fp-critical", findings.SeverityCritical),
		severity("fp-high-a", findings.SeverityHigh),
		severity("fp-high-b", findings.SeverityHigh),
		severity("fp-low", findings.SeverityLow),
		severity("fp-unknown", findings.SeverityUnknown),
	)
	empty := seedSucceededScan(t, ts, asset.Id)

	want := map[int64]gen.SeverityTotals{
		counted: {Critical: 1, High: 2, Medium: 0, Low: 1, Unknown: 1},
		empty:   {},
	}
	list := scanList(t, ts, cookie, "?asset_id="+itoa(asset.Id))
	if len(list.Scans) != 2 {
		t.Fatalf("scans = %+v, want 2", list.Scans)
	}
	for _, scan := range list.Scans {
		if scan.Counts != want[scan.Id] {
			t.Errorf("scan %d counts = %+v, want %+v", scan.Id, scan.Counts, want[scan.Id])
		}
	}

	// The single-scan read carries the same counts.
	read := decodeScan(t, ts.do(t, http.MethodGet, "/api/scans/"+itoa(counted), withCookie(cookie)))
	if read.Counts != want[counted] {
		t.Errorf("single scan counts = %+v, want %+v", read.Counts, want[counted])
	}
}

// TestCancelFinishedScanIsConflict covers the 409 contract of cancel.
func TestCancelFinishedScanIsConflict(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := pathAsset(t, ts, cookie)
	scanID := seedSucceededScan(t, ts, asset.Id)

	resp := doJSON(t, ts, http.MethodPost, "/api/scans/"+itoa(scanID)+"/cancel", nil, withBastion(cookie))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("cancel finished scan: status = %d, want %d: %s",
			resp.StatusCode, http.StatusConflict, readBody(t, resp))
	}
	if problem := readProblem(t, resp); problem.Detail == nil || *problem.Detail == "" {
		t.Error("cancel conflict has no detail")
	}

	resp = doJSON(t, ts, http.MethodPost, "/api/scans/9999/cancel", nil, withBastion(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cancel unknown scan: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestScanFindingsFiltersAndState covers the findings read and the decision
// endpoints, including the required reason.
func TestScanFindingsFiltersAndState(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := pathAsset(t, ts, cookie)

	high := findings.Finding{
		Fingerprint: "fp-high",
		Type:        findings.TypeSecret,
		Severity:    findings.SeverityHigh,
		Title:       "AWS key in config",
		Scanner:     "gitleaks",
		Occurrences: 1,
	}
	low := findings.Finding{
		Fingerprint: "fp-low",
		Type:        findings.TypeVulnerability,
		Severity:    findings.SeverityLow,
		Title:       "Outdated dependency",
		Scanner:     "trivy",
		Occurrences: 1,
	}
	scanID := seedSucceededScan(t, ts, asset.Id, high, low)

	read := func(query string) gen.FindingList {
		t.Helper()
		resp := ts.do(t, http.MethodGet, "/api/scans/"+itoa(scanID)+"/findings"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET findings%s: status = %d, want %d: %s",
				query, resp.StatusCode, http.StatusOK, readBody(t, resp))
		}
		return decodeFindings(t, readBody(t, resp))
	}

	if got := read(""); len(got.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2", got.Findings)
	}
	if got := read("?severity=high"); len(got.Findings) != 1 || got.Findings[0].Fingerprint != "fp-high" {
		t.Errorf("severity=high findings = %+v, want only fp-high", got.Findings)
	}
	if got := read("?type=vulnerability"); len(got.Findings) != 1 || got.Findings[0].Fingerprint != "fp-low" {
		t.Errorf("type=vulnerability findings = %+v, want only fp-low", got.Findings)
	}
	if got := read("?status=ignored"); len(got.Findings) != 0 {
		t.Errorf("status=ignored findings = %+v, want none before a decision", got.Findings)
	}

	resp := ts.do(t, http.MethodGet, "/api/scans/"+itoa(scanID)+"/findings?severity=bogus", withCookie(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid severity: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	resp = ts.do(t, http.MethodGet, "/api/scans/9999/findings", withCookie(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("findings of unknown scan: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	// A decision hides the finding and keeps the reason for review.
	resp = doJSON(t, ts, http.MethodPost, "/api/findings/fp-high/state", gen.SetFindingStateRequest{
		AssetId: asset.Id,
		State:   gen.FindingStateIgnored,
		Reason:  "test credential",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set state: status = %d, want %d: %s", resp.StatusCode, http.StatusNoContent, readBody(t, resp))
	}
	ignored := read("?status=ignored")
	if len(ignored.Findings) != 1 || ignored.Findings[0].State == nil || *ignored.Findings[0].State != gen.FindingStateIgnored {
		t.Fatalf("ignored findings = %+v, want fp-high with state ignored", ignored.Findings)
	}
	if ignored.Findings[0].Reason == nil || *ignored.Findings[0].Reason != "test credential" {
		t.Errorf("reason = %v, want the decision's reason", ignored.Findings[0].Reason)
	}
	if got := read("?status=open"); len(got.Findings) != 1 || got.Findings[0].Fingerprint != "fp-low" {
		t.Errorf("open findings = %+v, want only fp-low", got.Findings)
	}

	// A decision without a reason is refused: it must stay reviewable.
	resp = doJSON(t, ts, http.MethodPost, "/api/findings/fp-low/state", gen.SetFindingStateRequest{
		AssetId: asset.Id,
		State:   gen.FindingStateAcceptedRisk,
		Reason:  "   ",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blank reason: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if problem := readProblem(t, resp); problem.Detail == nil || *problem.Detail == "" {
		t.Error("blank reason problem has no detail")
	}

	// Clearing is a DELETE with asset_id: the decision key is per asset.
	resp = doJSON(t, ts, http.MethodDelete, "/api/findings/fp-high/state?asset_id="+itoa(asset.Id), nil, withBastion(cookie))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("clear state: status = %d, want %d: %s", resp.StatusCode, http.StatusNoContent, readBody(t, resp))
	}
	if got := read("?status=open"); len(got.Findings) != 2 {
		t.Errorf("open findings after clearing = %+v, want both", got.Findings)
	}
	if got := read("?status=ignored"); len(got.Findings) != 0 {
		t.Errorf("ignored findings after clearing = %+v, want none", got.Findings)
	}

	// An unknown asset id is not a decision target.
	resp = doJSON(t, ts, http.MethodPost, "/api/findings/fp-high/state", gen.SetFindingStateRequest{
		AssetId: 9999,
		State:   gen.FindingStateIgnored,
		Reason:  "nope",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("state for unknown asset: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestMutationsRequireCSRF: the X-Bastion CSRF guard also covers the new
// endpoints.
func TestMutationsRequireCSRF(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := pathAsset(t, ts, cookie)
	scanID := seedSucceededScan(t, ts, asset.Id)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "create asset", method: http.MethodPost, path: "/api/assets",
			body: gen.CreateAssetRequest{Kind: gen.CreateAssetRequestKindPath, Ref: t.TempDir()}},
		{name: "delete asset", method: http.MethodDelete, path: "/api/assets/" + itoa(asset.Id)},
		{name: "queue scan", method: http.MethodPost, path: "/api/scans",
			body: gen.CreateScansRequest{AssetIds: []int64{asset.Id}}},
		{name: "cancel scan", method: http.MethodPost, path: "/api/scans/" + itoa(scanID) + "/cancel"},
		{name: "set state", method: http.MethodPost, path: "/api/findings/fp/state",
			body: gen.SetFindingStateRequest{AssetId: asset.Id, State: gen.FindingStateIgnored, Reason: "r"}},
		{name: "clear state", method: http.MethodDelete,
			path: "/api/findings/fp/state?asset_id=" + itoa(asset.Id)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, ts, tc.method, tc.path, tc.body, withCookie(cookie))
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s without X-Bastion: status = %d, want %d",
					tc.method, tc.path, resp.StatusCode, http.StatusForbidden)
			}
		})
	}
}

// errFakeGitHub stands in for a GitHub failure.
var errFakeGitHub = errors.New("fake GitHub failure")
