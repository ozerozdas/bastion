package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// The tests in this file drive GET /api/scans/{id}/diff through the real
// server, so the generated query parsing, the service and the problem+json
// mapping are all covered.

// seedDiffScans seeds one asset with a succeeded scan, a failed scan and a
// succeeded scan that drops the critical finding, keeps the medium one and adds
// a high and a low one.
func seedDiffScans(t *testing.T, ts *testServer) (asset findings.Asset, ids [3]int64) {
	t.Helper()

	var err error
	asset, err = store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/diff", DisplayName: "Diff",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}

	ids[0] = seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(9),
		newReportFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical),
		newReportFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium))
	ids[1] = seedReportScan(t, ts.db, asset.ID, store.ScanStatusFailed, reportAt(10),
		newReportFinding(asset.ID, findings.TypeSecret, "private-key", findings.SeverityCritical))
	ids[2] = seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(11),
		newReportFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium),
		newReportFinding(asset.ID, findings.TypeLicense, "MIT", findings.SeverityLow),
		newReportFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh))
	return asset, ids
}

// diffRuleIDs reads a diff group's rule ids in order.
func diffRuleIDs(list []gen.Finding) []string {
	out := make([]string, 0, len(list))
	for _, finding := range list {
		out = append(out, *finding.RuleId)
	}
	return out
}

// TestGetScanDiffDefault covers the default baseline and the explicit one: the
// failed scan between the two succeeded ones must not be compared against.
func TestGetScanDiffDefault(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	_, ids := seedDiffScans(t, ts)
	first, second := ids[0], ids[2]

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "default against", path: fmt.Sprintf("/api/scans/%d/diff", second)},
		{name: "explicit against", path: fmt.Sprintf("/api/scans/%d/diff?against=%d", second, first)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, tc.path, withCookie(cookie))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
			}
			body := readBody(t, resp)
			var diff gen.ScanDiff
			if err := json.Unmarshal(body, &diff); err != nil {
				t.Fatalf("decode diff %q: %v", body, err)
			}

			if diff.ScanId != second {
				t.Errorf("scan_id = %d, want %d", diff.ScanId, second)
			}
			if diff.AgainstScanId == nil || *diff.AgainstScanId != first {
				t.Fatalf("against_scan_id = %v, want %d", diff.AgainstScanId, first)
			}

			if got, want := diffRuleIDs(diff.New), []string{"generic-api-key", "MIT"}; !slices.Equal(got, want) {
				t.Errorf("new = %v, want %v (most severe first)", got, want)
			}
			if got, want := diffRuleIDs(diff.Fixed), []string{"CVE-2026-0001"}; !slices.Equal(got, want) {
				t.Errorf("fixed = %v, want %v", got, want)
			}
			if got, want := diffRuleIDs(diff.Persisting), []string{"CVE-2026-0002"}; !slices.Equal(got, want) {
				t.Errorf("persisting = %v, want %v", got, want)
			}

			wantCounts := gen.ScanDiffCounts{
				New:        gen.SeverityTotals{High: 1, Low: 1},
				Fixed:      gen.SeverityTotals{Critical: 1},
				Persisting: gen.SeverityTotals{Medium: 1},
			}
			if diff.Counts != wantCounts {
				t.Errorf("counts = %+v, want %+v", diff.Counts, wantCounts)
			}

			// The findings reuse the shape of GET /api/scans/{id}/findings:
			// new and persisting belong to the second scan, fixed to the first.
			if diff.New[0].ScanId != second || diff.New[0].Status != gen.FindingStatusOpen {
				t.Errorf("new finding = %+v, want scan %d and status open", diff.New[0], second)
			}
			if diff.Fixed[0].ScanId != first {
				t.Errorf("fixed finding scan_id = %d, want %d", diff.Fixed[0].ScanId, first)
			}
			if diff.New[0].References == nil {
				t.Errorf("new finding references = nil, want []")
			}
		})
	}
}

// TestGetScanDiffFirstScan reports every finding as new when the asset has no
// earlier succeeded scan, and keeps the groups as arrays.
func TestGetScanDiffFirstScan(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/first", DisplayName: "First",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}
	scanID := seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(9),
		newReportFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical),
		newReportFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh))

	resp := ts.do(t, http.MethodGet, fmt.Sprintf("/api/scans/%d/diff", scanID), withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	body := readBody(t, resp)
	var diff gen.ScanDiff
	if err := json.Unmarshal(body, &diff); err != nil {
		t.Fatalf("decode diff %q: %v", body, err)
	}

	if diff.AgainstScanId != nil {
		t.Fatalf("against_scan_id = %d, want absent", *diff.AgainstScanId)
	}
	if got, want := diffRuleIDs(diff.New), []string{"CVE-2026-0001", "generic-api-key"}; !slices.Equal(got, want) {
		t.Errorf("new = %v, want %v", got, want)
	}
	if diff.Fixed == nil || diff.Persisting == nil {
		t.Errorf("fixed/persisting = %v/%v, want [] rather than null", diff.Fixed, diff.Persisting)
	}
	if len(diff.Fixed) != 0 || len(diff.Persisting) != 0 {
		t.Errorf("fixed/persisting = %v/%v, want empty", diff.Fixed, diff.Persisting)
	}
	wantCounts := gen.ScanDiffCounts{New: gen.SeverityTotals{Critical: 1, High: 1}}
	if diff.Counts != wantCounts {
		t.Errorf("counts = %+v, want %+v", diff.Counts, wantCounts)
	}
}

// TestGetScanDiffRejects covers the problem+json mapping: unknown ids are 404,
// a bad comparison is 400, a scan without a complete finding set is 409.
func TestGetScanDiffRejects(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	_, ids := seedDiffScans(t, ts)
	first, failed, second := ids[0], ids[1], ids[2]

	other, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindRepo, Ref: "octo/other", DisplayName: "Other",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(other): %v", err)
	}
	otherScan := seedReportScan(t, ts.db, other.ID, store.ScanStatusSucceeded, reportAt(12),
		newReportFinding(other.ID, findings.TypeVulnerability, "CVE-2026-0009", findings.SeverityHigh))

	cases := []struct {
		name   string
		path   string
		status int
	}{
		{name: "different assets", path: fmt.Sprintf("/api/scans/%d/diff?against=%d", second, otherScan), status: http.StatusBadRequest},
		{name: "against itself", path: fmt.Sprintf("/api/scans/%d/diff?against=%d", second, second), status: http.StatusBadRequest},
		{name: "negative against", path: fmt.Sprintf("/api/scans/%d/diff?against=-1", second), status: http.StatusBadRequest},
		{name: "zero against", path: fmt.Sprintf("/api/scans/%d/diff?against=0", second), status: http.StatusBadRequest},
		{name: "unknown scan", path: "/api/scans/999999/diff", status: http.StatusNotFound},
		{name: "unknown against", path: fmt.Sprintf("/api/scans/%d/diff?against=999999", second), status: http.StatusNotFound},
		{name: "current scan failed", path: fmt.Sprintf("/api/scans/%d/diff", failed), status: http.StatusConflict},
		{name: "against scan failed", path: fmt.Sprintf("/api/scans/%d/diff?against=%d", second, failed), status: http.StatusConflict},
		{name: "explicit success", path: fmt.Sprintf("/api/scans/%d/diff?against=%d", second, first), status: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, tc.path, withCookie(cookie))
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tc.status, readBody(t, resp))
			}
			if tc.status == http.StatusOK {
				return
			}
			problem := readProblem(t, resp)
			if problem.Status != tc.status {
				t.Errorf("problem status = %d, want %d", problem.Status, tc.status)
			}
		})
	}
}
