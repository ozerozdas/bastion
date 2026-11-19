package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// TestReportExtraHandlers covers the trend, runtimes and malware endpoints:
// their 200 shape, the days validation and the fixed report scoping.
func TestReportExtraHandlers(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, _ := seedInsightsAssets(t, ts.db)

	finishedAt := time.Now().UTC()
	vulnerability := newReportFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-3001", findings.SeverityCritical)
	secret := newReportFinding(alpha.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	eol := newReportFinding(alpha.ID, findings.TypeOutdated, "eol", findings.SeverityHigh)
	eol.PackageName = "python"
	eol.PackageVersion = "3.8"
	eol.Ecosystem = "python"
	eol.FixedVersion = "3.13"
	eol.Scanner = "endoflife.date"
	eol.Description = "Python 3.8 stopped receiving security updates on 2024-10-07."
	eol.Fingerprint = findings.Fingerprint(alpha.ID, eol)
	malware := newReportFinding(alpha.ID, findings.TypeMalware, "malware/evil-pkg", findings.SeverityCritical)
	malware.PackageName = "evil-pkg"
	malware.Fingerprint = findings.Fingerprint(alpha.ID, malware)
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, finishedAt,
		vulnerability, secret, eol, malware)

	read := func(path string) []byte {
		t.Helper()
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want %d: %s",
				path, resp.StatusCode, http.StatusOK, readBody(t, resp))
		}
		return readBody(t, resp)
	}

	// Trend: one point for the scanned day with every severity counted.
	var trend gen.ReportTrend
	if err := json.Unmarshal(read("/api/reports/trend?asset_id="+itoa(alpha.ID)), &trend); err != nil {
		t.Fatalf("decode trend: %v", err)
	}
	if len(trend.Series) != 1 {
		t.Fatalf("trend series = %+v, want alpha only", trend.Series)
	}
	series := trend.Series[0]
	if series.AssetId != alpha.ID || series.DisplayName != "Alpha" {
		t.Errorf("trend asset = %+v, want Alpha", series)
	}
	if len(series.Points) != 1 {
		t.Fatalf("trend points = %+v, want the scanned day", series.Points)
	}
	point := series.Points[0]
	if point.Date != finishedAt.Format(time.DateOnly) {
		t.Errorf("trend date = %q, want %q", point.Date, finishedAt.Format(time.DateOnly))
	}
	if point.Critical != 2 || point.High != 2 {
		t.Errorf("trend severities = %+v, want 2 critical and 2 high", point)
	}

	for _, query := range []string{"?days=0", "?days=366", "?asset_id=-1"} {
		resp := ts.do(t, http.MethodGet, "/api/reports/trend"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET /api/reports/trend%s: status = %d, want %d",
				query, resp.StatusCode, http.StatusBadRequest)
		}
	}

	// Runtimes: one grouped entry with the parsed end-of-life date.
	var runtimes gen.RuntimesReport
	if err := json.Unmarshal(read("/api/reports/runtimes"), &runtimes); err != nil {
		t.Fatalf("decode runtimes: %v", err)
	}
	if len(runtimes.Runtimes) != 1 {
		t.Fatalf("runtimes = %+v, want one entry", runtimes.Runtimes)
	}
	runtime := runtimes.Runtimes[0]
	if runtime.Name != "python" || runtime.Version != "3.8" || runtime.Ecosystem != "python" {
		t.Errorf("runtime = %+v, want python 3.8", runtime)
	}
	if runtime.EolDate == nil || *runtime.EolDate != "2024-10-07" {
		t.Errorf("eol_date = %v, want 2024-10-07", runtime.EolDate)
	}
	if runtime.FixedVersion == nil || *runtime.FixedVersion != "3.13" {
		t.Errorf("fixed_version = %v, want 3.13", runtime.FixedVersion)
	}
	if len(runtime.Assets) != 1 || runtime.Assets[0].AssetId != alpha.ID {
		t.Errorf("runtime assets = %+v, want alpha", runtime.Assets)
	}

	// Malware: the one open malware finding, not the other types.
	var report gen.MalwareReport
	if err := json.Unmarshal(read("/api/reports/malware"), &report); err != nil {
		t.Fatalf("decode malware: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("malware findings = %+v, want one", report.Findings)
	}
	if report.Findings[0].Type != gen.FindingType(findings.TypeMalware) ||
		report.Findings[0].PackageName == nil || *report.Findings[0].PackageName != "evil-pkg" {
		t.Errorf("malware finding = %+v, want evil-pkg", report.Findings[0])
	}
}
