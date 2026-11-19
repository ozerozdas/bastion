package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// getSLAThresholds reads the threshold settings.
func getSLAThresholds(t *testing.T, ts *testServer, cookie *http.Cookie) gen.SLAThresholds {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/api/settings/sla", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var thresholds gen.SLAThresholds
	if err := json.Unmarshal(readBody(t, resp), &thresholds); err != nil {
		t.Fatalf("decode thresholds: %v", err)
	}
	return thresholds
}

// TestSLASettingsRoundTrip is the settings contract: the seeded defaults are
// readable, a PUT without the CSRF header is refused, an out-of-range PUT is a
// 400 that writes nothing, and a valid PUT persists.
func TestSLASettingsRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	defaults := gen.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180}
	if got := getSLAThresholds(t, ts, cookie); got != defaults {
		t.Fatalf("defaults = %+v, want %+v", got, defaults)
	}

	// A mutating API request needs the CSRF header, like every other PUT.
	resp := doJSON(t, ts, http.MethodPut, "/api/settings/sla", gen.SLAThresholds{
		Critical: 3, High: 14, Medium: 45, Low: 120,
	}, withCookie(cookie))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT without CSRF status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	// An explicit zero fails the 1..3650 bound and is named in the detail.
	resp = doJSON(t, ts, http.MethodPut, "/api/settings/sla", gen.SLAThresholds{
		Critical: 0, High: 30, Medium: 90, Low: 180,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid PUT status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if problem := readProblem(t, resp); !strings.Contains(problemDetail(problem), "critical") {
		t.Fatalf("invalid PUT detail = %q, want it to name critical", problemDetail(problem))
	}
	if got := getSLAThresholds(t, ts, cookie); got != defaults {
		t.Fatalf("thresholds after rejected write = %+v, want %+v", got, defaults)
	}

	want := gen.SLAThresholds{Critical: 3, High: 14, Medium: 45, Low: 120}
	resp = doJSON(t, ts, http.MethodPut, "/api/settings/sla", want, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var stored gen.SLAThresholds
	if err := json.Unmarshal(readBody(t, resp), &stored); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if stored != want {
		t.Fatalf("PUT response = %+v, want %+v", stored, want)
	}
	if got := getSLAThresholds(t, ts, cookie); got != want {
		t.Fatalf("persisted thresholds = %+v, want %+v", got, want)
	}
}

// TestSLAReportEmptyInstall covers the report handler's shape on a fresh
// install and the window validation.
func TestSLAReportEmptyInstall(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/reports/sla", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var report gen.SLAReport
	if err := json.Unmarshal(readBody(t, resp), &report); err != nil {
		t.Fatalf("decode SLA report: %v", err)
	}
	if report.Thresholds != (gen.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180}) {
		t.Errorf("thresholds = %+v, want defaults", report.Thresholds)
	}
	if report.Overdue == nil || len(report.Overdue) != 0 {
		t.Errorf("overdue = %v, want an empty array", report.Overdue)
	}
	if report.OpenCount != 0 || report.OverdueCount != 0 || report.FixedInWindow != 0 {
		t.Errorf("empty counts = %+v, want zero", report)
	}
	if report.MeanTimeToFixDays != nil {
		t.Errorf("mean_time_to_fix_days = %v, want null", report.MeanTimeToFixDays)
	}

	resp = ts.do(t, http.MethodGet, "/api/reports/sla?days=366", withCookie(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("days=366 status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
