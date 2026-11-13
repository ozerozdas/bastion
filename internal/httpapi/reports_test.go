package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// The tests in this file drive /api/findings and /api/reports/dashboard through
// the real server: session cookie, generated request parsing and problem+json
// mapping included.

// seedReportScan persists one finished scan of assetID and returns its id.
func seedReportScan(t *testing.T, db *sql.DB, assetID int64, status string, finishedAt time.Time, list ...findings.Finding) int64 {
	t.Helper()

	scanID, err := store.StartScan(t.Context(), db, assetID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan(asset %d): %v", assetID, err)
	}
	if err := store.SaveScanResult(t.Context(), db, scanID, store.ScanResult{
		Status:     status,
		FinishedAt: finishedAt,
		Findings:   list,
	}); err != nil {
		t.Fatalf("SaveScanResult(scan %d): %v", scanID, err)
	}
	return scanID
}

// newReportFinding builds a normalized finding with a stable fingerprint.
func newReportFinding(assetID int64, kind findings.Type, ruleID string, severity findings.Severity) findings.Finding {
	finding := findings.Finding{
		AssetID:     assetID,
		Type:        kind,
		RuleID:      ruleID,
		Severity:    severity,
		Title:       "example finding " + ruleID,
		PackageName: "example",
		Ecosystem:   "go",
		Scanner:     "trivy",
		Occurrences: 1,
	}
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// reportAt is a UTC timestamp on the seeded day; the hour orders the scans.
func reportAt(hour int) time.Time {
	return time.Date(2026, 11, 10, hour, 0, 0, 0, time.UTC)
}

// decodeFindings decodes a FindingList response.
func decodeFindings(t *testing.T, body []byte) gen.FindingList {
	t.Helper()

	var list gen.FindingList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode finding list %q: %v", body, err)
	}
	return list
}

// seedFindingsFixture seeds two assets whose latest succeeded scans differ from
// their first ones, plus an ignored finding.
func seedFindingsFixture(t *testing.T, ts *testServer) (alpha, beta findings.Asset, secretScanID int64) {
	t.Helper()

	var err error
	alpha, err = store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/alpha", DisplayName: "Alpha",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(alpha): %v", err)
	}
	beta, err = store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindRepo, Ref: "octo/beta", DisplayName: "Beta",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(beta): %v", err)
	}

	// The first alpha scan's findings are superseded by the second scan and
	// must not appear in the latest list.
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(9),
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical),
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium))

	secret := newReportFinding(alpha.ID, findings.TypeSecret, "gitleaks-generic-api-key", findings.SeverityHigh)
	secretScanID = seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(10),
		secret,
		newReportFinding(alpha.ID, findings.TypeLicense, "MIT", findings.SeverityLow))

	if err := store.SetFindingState(t.Context(), ts.db, alpha.ID, secret.Fingerprint,
		store.FindingStateIgnored, "accepted upstream"); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	seedReportScan(t, ts.db, beta.ID, store.ScanStatusSucceeded, reportAt(11),
		newReportFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0003", findings.SeverityMedium))

	return alpha, beta, secretScanID
}

// TestListFindingsFilters covers every query parameter and the exact latest-scan
// semantics: the ignored secret is listed as ignored, the superseded scan is
// not listed at all.
func TestListFindingsFilters(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta, secretScanID := seedFindingsFixture(t, ts)

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{name: "no filter", query: "", want: 3},
		{name: "asset", query: "?asset_id=" + itoa(alpha.ID), want: 2},
		{name: "other asset", query: "?asset_id=" + itoa(beta.ID), want: 1},
		{name: "severity", query: "?severity=high", want: 1},
		{name: "type", query: "?type=secret", want: 1},
		{name: "status ignored", query: "?status=ignored", want: 1},
		{name: "status open", query: "?status=open", want: 2},
		{name: "type and severity", query: "?type=vulnerability&severity=medium", want: 1},
		{name: "unknown asset", query: "?asset_id=999", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, "/api/findings"+tc.query, withCookie(cookie))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			list := decodeFindings(t, readBody(t, resp))
			if len(list.Findings) != tc.want {
				t.Fatalf("findings = %+v, want %d", list.Findings, tc.want)
			}
			if list.Findings == nil {
				t.Fatal("findings is null, want a list")
			}
		})
	}

	// The default order is most severe first; the ignored secret still leads
	// because severity, not status, orders the list.
	resp := ts.do(t, http.MethodGet, "/api/findings", withCookie(cookie))
	list := decodeFindings(t, readBody(t, resp))
	if len(list.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(list.Findings))
	}
	first := list.Findings[0]
	if first.Type != gen.Secret || first.Severity != gen.SeverityHigh {
		t.Errorf("first finding = %+v, want the high secret", first)
	}
	if first.Status != gen.FindingStatusIgnored {
		t.Errorf("first.status = %q, want ignored", first.Status)
	}
	if first.State == nil || *first.State != gen.FindingStateIgnored {
		t.Errorf("first.state = %v, want ignored", first.State)
	}
	if first.Reason == nil || *first.Reason != "accepted upstream" {
		t.Errorf("first.reason = %v, want the recorded reason", first.Reason)
	}
	if first.ScanId != secretScanID {
		t.Errorf("first.scan_id = %d, want %d", first.ScanId, secretScanID)
	}
	if first.Fingerprint == "" || first.References == nil || first.Occurrences != 1 {
		t.Errorf("first finding = %+v, want fingerprint, [] references and one occurrence", first)
	}

	// Filtering by the effective status keeps the inverse set.
	resp = ts.do(t, http.MethodGet, "/api/findings?status=open", withCookie(cookie))
	open := decodeFindings(t, readBody(t, resp))
	for _, finding := range open.Findings {
		if finding.Status != gen.FindingStatusOpen {
			t.Errorf("open filter returned %+v", finding)
		}
	}
	if open.Findings[0].AssetId != beta.ID {
		t.Errorf("first open finding asset = %d, want %d", open.Findings[0].AssetId, beta.ID)
	}
}

// TestListFindingsRejectsBadEnums proves every enum parameter is validated and
// answered with problem+json, not a 500 or an empty list.
func TestListFindingsRejectsBadEnums(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	cases := []struct {
		query  string
		detail string
	}{
		{query: "?severity=urgent", detail: "severity"},
		{query: "?type=bogus", detail: "type"},
		{query: "?status=muted", detail: "status"},
		{query: "?asset_id=-1", detail: "asset_id"},
	}
	for _, tc := range cases {
		t.Run(url.QueryEscape(tc.query), func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, "/api/findings"+tc.query, withCookie(cookie))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want %d", tc.query, resp.StatusCode, http.StatusBadRequest)
			}
			problem := readProblem(t, resp)
			if problem.Status != http.StatusBadRequest || problem.Title != "Bad Request" {
				t.Errorf("%s: problem = %+v, want a 400 Bad Request", tc.query, problem)
			}
			if problem.Detail == nil || !strings.Contains(*problem.Detail, tc.detail) {
				t.Errorf("%s: detail = %v, want it to mention %q", tc.query, problem.Detail, tc.detail)
			}
		})
	}
}

// TestGetDashboard serves the aggregates the dashboard renders.
func TestGetDashboard(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	alpha, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/alpha", DisplayName: "Alpha",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(alpha): %v", err)
	}
	beta, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindRepo, Ref: "octo/beta", DisplayName: "Beta",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(beta): %v", err)
	}

	criticalScan := seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(10),
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical))
	mediumScan := seedReportScan(t, ts.db, beta.ID, store.ScanStatusSucceeded, reportAt(11),
		newReportFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium))

	resp := ts.do(t, http.MethodGet, "/api/reports/dashboard", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body := readBody(t, resp)
	var dashboard gen.Dashboard
	if err := json.Unmarshal(body, &dashboard); err != nil {
		t.Fatalf("decode dashboard %q: %v", body, err)
	}

	wantSeverity := gen.SeverityTotals{Critical: 1, High: 0, Medium: 1, Low: 0, Unknown: 0}
	if dashboard.TotalsBySeverity != wantSeverity {
		t.Errorf("totals_by_severity = %+v, want %+v", dashboard.TotalsBySeverity, wantSeverity)
	}
	wantTypes := gen.TypeTotals{Vulnerability: 2}
	if dashboard.TotalsByType != wantTypes {
		t.Errorf("totals_by_type = %+v, want %+v", dashboard.TotalsByType, wantTypes)
	}

	wantAssets := []gen.AssetRisk{
		{AssetId: alpha.ID, DisplayName: "Alpha", Kind: gen.AssetKindPath, Score: 1000, Critical: 1},
		{AssetId: beta.ID, DisplayName: "Beta", Kind: gen.AssetKindRepo, Score: 10, Medium: 1},
	}
	if len(dashboard.TopAssets) != len(wantAssets) {
		t.Fatalf("top_assets = %+v, want %+v", dashboard.TopAssets, wantAssets)
	}
	for i, want := range wantAssets {
		if dashboard.TopAssets[i] != want {
			t.Errorf("top_assets[%d] = %+v, want %+v", i, dashboard.TopAssets[i], want)
		}
	}

	if len(dashboard.Trend) != 2 || len(dashboard.Trend[0].Scans) != 1 || len(dashboard.Trend[1].Scans) != 1 {
		t.Fatalf("trend = %+v, want one point per asset", dashboard.Trend)
	}
	if dashboard.Trend[0].Scans[0].ScanId != criticalScan || dashboard.Trend[0].Scans[0].CriticalHighOpen != 1 {
		t.Errorf("alpha trend = %+v, want scan %d with one open critical", dashboard.Trend[0].Scans, criticalScan)
	}
	if dashboard.Trend[1].Scans[0].ScanId != mediumScan || dashboard.Trend[1].Scans[0].CriticalHighOpen != 0 {
		t.Errorf("beta trend = %+v, want scan %d with no open critical+high", dashboard.Trend[1].Scans, mediumScan)
	}

	if len(dashboard.LastScans) != 2 {
		t.Fatalf("last_scans = %+v, want one per asset", dashboard.LastScans)
	}
	if dashboard.LastScans[0].ScanId != criticalScan || dashboard.LastScans[0].Status != gen.ScanStatusSucceeded {
		t.Errorf("alpha last scan = %+v, want scan %d succeeded", dashboard.LastScans[0], criticalScan)
	}
	if dashboard.LastScans[0].FinishedAt == nil {
		t.Error("last scan finished_at is absent, want the scan's finish time")
	}
}

// itoa formats an id for a query string.
func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
