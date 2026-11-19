package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
	"github.com/ozerozdas/bastion/internal/store"
)

// licenseReportFinding builds a licence finding for the handler fixtures.
func licenseReportFinding(assetID int64, licence, pkg, version string) findings.Finding {
	finding := newReportFinding(assetID, findings.TypeLicense, licence, findings.SeverityHigh)
	finding.PackageName = pkg
	finding.PackageVersion = version
	finding.Ecosystem = "npm"
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// seedTriggeredReportScan persists one finished scan with an explicit trigger.
func seedTriggeredReportScan(t *testing.T, db *sql.DB, assetID int64, trigger string,
	list ...findings.Finding) int64 {
	t.Helper()

	scanID, err := store.StartScan(t.Context(), db, assetID, trigger)
	if err != nil {
		t.Fatalf("StartScan(asset %d): %v", assetID, err)
	}
	if err := store.SaveScanResult(t.Context(), db, scanID, store.ScanResult{
		Status:     store.ScanStatusSucceeded,
		FinishedAt: reportAt(12),
		ScannerRuns: []store.ScannerRun{
			{Scanner: "trivy", Status: store.ScanStatusSucceeded},
		},
		Findings: list,
	}); err != nil {
		t.Fatalf("SaveScanResult(scan %d): %v", scanID, err)
	}
	return scanID
}

// TestReportLicensesHandlerAndCSV covers the licence inventory's JSON shape,
// the policy join, the hand-written CSV download and the bad-asset problem.
func TestReportLicensesHandlerAndCSV(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta := seedInsightsAssets(t, ts.db)

	policies, err := licencepolicy.NewService(ts.db)
	if err != nil {
		t.Fatalf("licencepolicy.NewService: %v", err)
	}
	if _, err := policies.Replace(t.Context(), nil, licencepolicy.Policy{
		Allow: []string{"Apache-2.0"},
		Deny:  []string{"GPL-3.0"},
	}); err != nil {
		t.Fatalf("Replace(global): %v", err)
	}
	alphaID := alpha.ID
	if _, err := policies.Replace(t.Context(), &alphaID, licencepolicy.Policy{
		Allow: []string{"GPL-3.0"},
	}); err != nil {
		t.Fatalf("Replace(alpha): %v", err)
	}

	seedTriggeredReportScan(t, ts.db, alpha.ID, store.ScanTriggerCLI,
		licenseReportFinding(alpha.ID, "GPL-3.0", "alpha-gpl", "1.0.0"),
		licenseReportFinding(alpha.ID, "Apache-2.0", "alpha-web", "1.0.0"))
	seedTriggeredReportScan(t, ts.db, beta.ID, store.ScanTriggerCLI,
		licenseReportFinding(beta.ID, "GPL-3.0", "beta-gpl", "2.0.0"))

	resp := ts.do(t, http.MethodGet, "/api/reports/licenses", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var report gen.LicensesReport
	if err := json.Unmarshal(readBody(t, resp), &report); err != nil {
		t.Fatalf("decode licences: %v", err)
	}
	if len(report.Licenses) != 3 {
		t.Fatalf("licenses = %+v, want three entries", report.Licenses)
	}
	// Deny first: the global GPL rule applies to beta, while alpha's override
	// keeps its own GPL finding allowed.
	if report.Licenses[0].License != "GPL-3.0" ||
		string(report.Licenses[0].Policy) != "deny" ||
		len(report.Licenses[0].Items) != 1 ||
		report.Licenses[0].Items[0].DisplayName != "Beta" {
		t.Errorf("first entry = %+v, want beta's denied GPL", report.Licenses[0])
	}
	allowedGPL := false
	allowedApache := false
	for _, entry := range report.Licenses {
		if entry.License == "GPL-3.0" && string(entry.Policy) == "allow" {
			allowedGPL = true
		}
		if entry.License == "Apache-2.0" && string(entry.Policy) == "allow" {
			allowedApache = true
		}
	}
	if !allowedGPL || !allowedApache {
		t.Errorf("licenses = %+v, want both allow entries included", report.Licenses)
	}

	csv := ts.do(t, http.MethodGet, "/api/reports/licenses.csv", withCookie(cookie))
	if csv.StatusCode != http.StatusOK {
		t.Fatalf("CSV status = %d, want %d: %s", csv.StatusCode, http.StatusOK, readBody(t, csv))
	}
	if got, want := csv.Header.Get("Content-Type"), "text/csv; charset=utf-8"; got != want {
		t.Errorf("CSV Content-Type = %q, want %q", got, want)
	}
	disposition := csv.Header.Get("Content-Disposition")
	if !strings.HasPrefix(disposition, `attachment; filename="bastion-licenses-`) ||
		!strings.HasSuffix(disposition, `.csv"`) {
		t.Errorf("CSV Content-Disposition = %q, want a licence attachment", disposition)
	}
	body := string(readBody(t, csv))
	if !strings.HasPrefix(body, "\uFEFFlicense,policy,package,version,ecosystem,asset\r\n") {
		t.Errorf("CSV header = %q, want the licence columns", firstLine(body))
	}
	for _, row := range []string{
		"GPL-3.0,deny,beta-gpl,2.0.0,npm,Beta",
		"GPL-3.0,allow,alpha-gpl,1.0.0,npm,Alpha",
		"Apache-2.0,allow,alpha-web,1.0.0,npm,Alpha",
	} {
		if !strings.Contains(body, row) {
			t.Errorf("CSV body is missing row %q:\n%s", row, body)
		}
	}

	for _, path := range []string{"/api/reports/licenses?asset_id=-1", "/api/reports/licenses.csv?asset_id=-1"} {
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want %d", path, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

// TestReportAuditHandler covers the audit pack's asset, summary, cap flag and
// fix plan, the fleet pack, and the problem responses.
func TestReportAuditHandler(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, _ := seedInsightsAssets(t, ts.db)

	critical := newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-9200", findings.SeverityCritical)
	critical.PackageVersion = "1.0.0"
	critical.FixedVersion = "1.2.0"
	critical.Fingerprint = findings.Fingerprint(alpha.ID, critical)
	ignored := newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-9201", findings.SeverityHigh)
	seedTriggeredReportScan(t, ts.db, alpha.ID, store.ScanTriggerCLI, critical, ignored)
	if err := store.SetFindingState(t.Context(), ts.db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	resp := ts.do(t, http.MethodGet, "/api/reports/audit?asset_id="+itoa(alpha.ID), withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var report gen.AuditReport
	if err := json.Unmarshal(readBody(t, resp), &report); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if report.Asset == nil || report.Asset.AssetId != alpha.ID || report.Asset.DisplayName != "Alpha" {
		t.Errorf("asset = %+v, want alpha", report.Asset)
	}
	if report.Summary.Total != 1 || report.Summary.Critical != 1 || report.Summary.High != 0 {
		t.Errorf("summary = %+v, want the one open critical finding", report.Summary)
	}
	if len(report.Findings) != 1 || report.Truncated {
		t.Errorf("findings = %d truncated = %v, want one finding and no cap", len(report.Findings), report.Truncated)
	}
	if len(report.FixPlan.Steps) != 1 || report.FixPlan.Steps[0].FindingCount != 1 {
		t.Errorf("fix plan = %+v, want one step", report.FixPlan)
	}

	// The fleet pack has no asset and no fix plan.
	fleet := ts.do(t, http.MethodGet, "/api/reports/audit", withCookie(cookie))
	if fleet.StatusCode != http.StatusOK {
		t.Fatalf("fleet GET status = %d, want %d", fleet.StatusCode, http.StatusOK)
	}
	var fleetReport gen.AuditReport
	if err := json.Unmarshal(readBody(t, fleet), &fleetReport); err != nil {
		t.Fatalf("decode fleet audit: %v", err)
	}
	if fleetReport.Asset != nil {
		t.Errorf("fleet asset = %+v, want null", fleetReport.Asset)
	}
	if fleetReport.Summary.Total != 1 || len(fleetReport.FixPlan.Steps) != 0 {
		t.Errorf("fleet pack = %+v, want one finding and no fix plan", fleetReport)
	}

	for path, status := range map[string]int{
		"/api/reports/audit?asset_id=424242": http.StatusNotFound,
		"/api/reports/audit?asset_id=-1":     http.StatusBadRequest,
	} {
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != status {
			t.Errorf("GET %s: status = %d, want %d", path, resp.StatusCode, status)
		}
	}
}

// TestReportCIHistoryHandler covers the trigger filter, the default and
// explicit limit, and the bad-limit problem.
func TestReportCIHistoryHandler(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta := seedInsightsAssets(t, ts.db)

	seedTriggeredReportScan(t, ts.db, alpha.ID, store.ScanTriggerCLI,
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-9300", findings.SeverityCritical))
	seedTriggeredReportScan(t, ts.db, beta.ID, store.ScanTriggerAPI,
		newReportFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-9301", findings.SeverityMedium))
	seedTriggeredReportScan(t, ts.db, alpha.ID, "ui",
		newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-9302", findings.SeverityCritical))

	resp := ts.do(t, http.MethodGet, "/api/reports/ci-history", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var report gen.CIHistoryReport
	if err := json.Unmarshal(readBody(t, resp), &report); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(report.Runs) != 2 {
		t.Fatalf("runs = %+v, want the CLI and API scans only", report.Runs)
	}
	triggers := map[string]bool{}
	for _, run := range report.Runs {
		triggers[string(run.Trigger)] = true
		if run.DurationMs != nil {
			t.Errorf("run %d duration = %v, want null without started_at", run.ScanId, run.DurationMs)
		}
	}
	if !triggers["cli"] || !triggers["api"] || triggers["ui"] {
		t.Errorf("triggers = %v, want cli and api but no ui", triggers)
	}

	limited := ts.do(t, http.MethodGet, "/api/reports/ci-history?limit=1", withCookie(cookie))
	if limited.StatusCode != http.StatusOK {
		t.Fatalf("limit=1 status = %d, want %d", limited.StatusCode, http.StatusOK)
	}
	var limitedReport gen.CIHistoryReport
	if err := json.Unmarshal(readBody(t, limited), &limitedReport); err != nil {
		t.Fatalf("decode limited history: %v", err)
	}
	if len(limitedReport.Runs) != 1 {
		t.Errorf("limit=1 runs = %d, want 1", len(limitedReport.Runs))
	}

	for _, query := range []string{"?limit=0", "?limit=201", "?asset_id=-1"} {
		resp := ts.do(t, http.MethodGet, "/api/reports/ci-history"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET /api/reports/ci-history%s: status = %d, want %d",
				query, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

// TestReportHandlersRejectNonPositiveAssetID covers the asset_id contract every
// /api/reports/* endpoint shares: the spec's minimum is 1, so a zero (which the
// service would otherwise read as the whole fleet) and a negative id are 400.
func TestReportHandlersRejectNonPositiveAssetID(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	for _, path := range []string{
		"/api/reports/owasp-top10?asset_id=0",
		"/api/reports/owasp-top10?asset_id=-1",
		"/api/reports/cve-insights?cve=CVE-2021-44228&asset_id=0",
		"/api/reports/trend?asset_id=0",
		"/api/reports/runtimes?asset_id=0",
		"/api/reports/malware?asset_id=0",
		"/api/reports/sla?asset_id=0",
		"/api/reports/licenses?asset_id=0",
		"/api/reports/licenses.csv?asset_id=0",
		"/api/reports/audit?asset_id=0",
		"/api/reports/ci-history?asset_id=0",
	} {
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want %d: %s",
				path, resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
			continue
		}
		_ = readBody(t, resp)
	}
}
