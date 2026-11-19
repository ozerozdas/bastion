package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// seedInsightsAsset creates the two assets the report handler tests use.
func seedInsightsAssets(t *testing.T, db *sql.DB) (alpha, beta findings.Asset) {
	t.Helper()

	var err error
	alpha, err = store.GetOrCreateAsset(t.Context(), db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/insights-alpha", DisplayName: "Alpha",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(alpha): %v", err)
	}
	beta, err = store.GetOrCreateAsset(t.Context(), db, findings.Asset{
		Kind: findings.AssetKindRepo, Ref: "octo/insights-beta", DisplayName: "Beta",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(beta): %v", err)
	}
	return alpha, beta
}

// TestGetOWASPTop10Handler covers the report shape, the category order, the
// asset filter and the invalid-asset problem.
func TestGetOWASPTop10Handler(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta := seedInsightsAssets(t, ts.db)

	injection := newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-2001", findings.SeverityHigh)
	injection.CWE = []string{"CWE-79"}
	sast := newReportFinding(alpha.ID, findings.TypeSAST, "go/sql-injection", findings.SeverityMedium)
	sast.CWE = []string{"CWE-89"}
	unmapped := newReportFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(10), injection, sast, unmapped)

	access := newReportFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-2002", findings.SeverityLow)
	access.CWE = []string{"CWE-22"}
	seedReportScan(t, ts.db, beta.ID, store.ScanStatusSucceeded, reportAt(9), access)

	read := func(query string) gen.OWASPTop10 {
		t.Helper()
		resp := ts.do(t, http.MethodGet, "/api/reports/owasp-top10"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want %d: %s",
				query, resp.StatusCode, http.StatusOK, readBody(t, resp))
		}
		var report gen.OWASPTop10
		if err := json.Unmarshal(readBody(t, resp), &report); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		return report
	}

	wantOrder := []string{
		"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "unmapped",
	}
	scoped := read("?asset_id=" + itoa(alpha.ID))
	if len(scoped.Categories) != len(wantOrder) {
		t.Fatalf("categories = %d, want %d", len(scoped.Categories), len(wantOrder))
	}
	wantScoped := map[string]int{"A03": 2, "unmapped": 1}
	for i, category := range scoped.Categories {
		if category.Id != wantOrder[i] {
			t.Errorf("category %d = %q, want %q", i, category.Id, wantOrder[i])
		}
		if category.Count != len(category.Findings) {
			t.Errorf("category %q count = %d, findings = %d",
				category.Id, category.Count, len(category.Findings))
		}
		if got := category.Count; got != wantScoped[category.Id] {
			t.Errorf("category %q count = %d, want %d", category.Id, got, wantScoped[category.Id])
		}
	}
	if scoped.Categories[2].Findings[0].AssetId != alpha.ID {
		t.Errorf("A03 finding asset = %d, want %d", scoped.Categories[2].Findings[0].AssetId, alpha.ID)
	}

	all := read("")
	if all.Categories[0].Count != 1 || all.Categories[2].Count != 2 || all.Categories[10].Count != 1 {
		t.Errorf("all counts = A01 %d, A03 %d, unmapped %d; want 1, 2, 1",
			all.Categories[0].Count, all.Categories[2].Count, all.Categories[10].Count)
	}

	resp := ts.do(t, http.MethodGet, "/api/reports/owasp-top10?asset_id=-1", withCookie(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative asset status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if problem := readProblem(t, resp); problem.Detail == nil || *problem.Detail == "" {
		t.Error("negative asset problem has no detail")
	}
}

// TestGetCVEInsightsHandler covers the response shape, the null EPSS score,
// the case-insensitive id, asset scoping and the invalid-id problem.
func TestGetCVEInsightsHandler(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta := seedInsightsAssets(t, ts.db)

	log4j := func(assetID int64) findings.Finding {
		finding := newReportFinding(assetID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical)
		finding.PackageName = "log4j-core"
		finding.PackageVersion = "2.14.0"
		finding.FixedVersion = "2.17.0"
		finding.Fingerprint = findings.Fingerprint(assetID, finding)
		return finding
	}
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(9), log4j(alpha.ID))
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(10), log4j(alpha.ID))
	seedReportScan(t, ts.db, beta.ID, store.ScanStatusSucceeded, reportAt(8), log4j(beta.ID))

	read := func(query string) (gen.CVEInsights, []byte) {
		t.Helper()
		resp := ts.do(t, http.MethodGet, "/api/reports/cve-insights"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want %d: %s",
				query, resp.StatusCode, http.StatusOK, readBody(t, resp))
		}
		body := readBody(t, resp)
		var insights gen.CVEInsights
		if err := json.Unmarshal(body, &insights); err != nil {
			t.Fatalf("decode insights: %v", err)
		}
		return insights, body
	}

	insights, body := read("?cve=cve-2021-44228")
	if insights.Cve != "CVE-2021-44228" {
		t.Errorf("cve = %q, want the normalized id", insights.Cve)
	}
	if insights.Epss != nil {
		t.Errorf("epss = %+v, want nil without a feed", insights.Epss)
	}
	if !strings.Contains(string(body), `"epss":null`) {
		t.Errorf("body = %s, want an explicit null epss", body)
	}
	if len(insights.Assets) != 2 {
		t.Fatalf("assets = %+v, want alpha and beta", insights.Assets)
	}
	first := insights.Assets[0]
	if first.AssetId != alpha.ID || first.DisplayName != "Alpha" || first.Kind != gen.AssetKind(findings.AssetKindPath) {
		t.Errorf("first asset = %+v, want Alpha", first)
	}
	if first.PackageName == nil || *first.PackageName != "log4j-core" ||
		first.PackageVersion == nil || *first.PackageVersion != "2.14.0" ||
		first.FixedVersion == nil || *first.FixedVersion != "2.17.0" {
		t.Errorf("first asset = %+v, want the package fields", first)
	}
	if first.FirstSeen == nil || !first.FirstSeen.Equal(reportAt(9)) {
		t.Errorf("first_seen = %v, want %v", first.FirstSeen, reportAt(9))
	}

	scoped, _ := read("?cve=CVE-2021-44228&asset_id=" + itoa(beta.ID))
	if len(scoped.Assets) != 1 || scoped.Assets[0].AssetId != beta.ID {
		t.Errorf("scoped assets = %+v, want beta only", scoped.Assets)
	}

	for _, query := range []string{"?cve=log4j", "?cve=CVE-2021-123", "?asset_id=1"} {
		resp := ts.do(t, http.MethodGet, "/api/reports/cve-insights"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want %d", query, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

// TestGetCVEInsightsCarriesEPSS proves the report reads the cached feed.
func TestGetCVEInsightsCarriesEPSS(t *testing.T) {
	var hits atomic.Int32
	feed := epssTestService(t, &hits)
	if err := feed.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	feed.Status()

	ts := newTestServerWithEPSS(t, feed)
	cookie := ts.login(t)
	alpha, _ := seedInsightsAssets(t, ts.db)
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(9),
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical))

	resp := ts.do(t, http.MethodGet, "/api/reports/cve-insights?cve=CVE-2021-44228", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var insights gen.CVEInsights
	if err := json.Unmarshal(readBody(t, resp), &insights); err != nil {
		t.Fatalf("decode insights: %v", err)
	}
	if insights.Epss == nil || insights.Epss.Score != 0.99999 || insights.Epss.Percentile != 1.0 {
		t.Fatalf("epss = %+v, want the fixture score", insights.Epss)
	}
}
