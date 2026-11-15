package httpapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

const epssFixture = `#model_version:v2026.06.15,score_date:2026-11-15T12:03:04Z
cve,epss,percentile
CVE-2021-44228,0.99999,1.0
`

// epssTestService serves a fixture feed and counts requests. The inline
// spawner makes a Status() call finish its refresh before it returns.
func epssTestService(t *testing.T, hits *atomic.Int32) *epss.Service {
	t.Helper()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(epssFixture)); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close feed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(compressed.Bytes())
	}))
	t.Cleanup(server.Close)

	return epss.New(epss.Config{
		DataDir:  t.TempDir(),
		CacheDir: t.TempDir(),
		URL:      server.URL,
		Version:  "test",
		Spawn:    func(f func()) { f() },
	})
}

func readEPSSStatus(t *testing.T, resp *http.Response) gen.EPSSStatus {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var status gen.EPSSStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode EPSS status: %v", err)
	}
	return status
}

func TestEPSSOffMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithEPSS(t, epssTestService(t, &hits))
	cookie := ts.login(t)

	status := readEPSSStatus(t, ts.do(t, http.MethodGet, "/api/epss", withCookie(cookie)))
	if status.Enabled {
		t.Error("enabled = true on a fresh install")
	}
	if status.Count != nil {
		t.Errorf("count = %d, want absent", *status.Count)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("feed requests = %d, want 0 with EPSS off", got)
	}
}

func TestSetEPSSEnabledDownloads(t *testing.T) {
	var hits atomic.Int32
	ts := newTestServerWithEPSS(t, epssTestService(t, &hits))
	cookie := ts.login(t)

	enabled := readEPSSStatus(t, ts.doJSON(t, http.MethodPut, "/api/epss", `{"enabled":true}`, cookie, true))
	if !enabled.Enabled {
		t.Error("enabled = false after opting in")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("feed requests = %d, want 1", got)
	}

	// The response to PUT carries the state before the refresh it started, so
	// the next read shows the cached feed.
	status := readEPSSStatus(t, ts.do(t, http.MethodGet, "/api/epss", withCookie(cookie)))
	if status.Count == nil || *status.Count != 1 {
		t.Fatalf("count = %v, want 1", status.Count)
	}
	if status.ScoreDate == nil || *status.ScoreDate != "2026-11-15T12:03:04Z" {
		t.Errorf("score_date = %v", status.ScoreDate)
	}

	off := readEPSSStatus(t, ts.doJSON(t, http.MethodPut, "/api/epss", `{"enabled":false}`, cookie, true))
	if off.Enabled {
		t.Error("enabled = true after opting out")
	}
}

func TestFindingsCarryEPSS(t *testing.T) {
	var hits atomic.Int32
	feed := epssTestService(t, &hits)
	if err := feed.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	feed.Status()

	ts := newTestServerWithEPSS(t, feed)
	cookie := ts.login(t)

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind:        findings.AssetKindPath,
		Ref:         "/tmp/epss-finding",
		DisplayName: "epss-finding",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}
	finding := newReportFinding(asset.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical)
	finding.PackageVersion = "2.14.0"
	finding.FixedVersion = "2.17.0"
	seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(12), finding)

	resp := ts.do(t, http.MethodGet, "/api/findings", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("findings status = %d", resp.StatusCode)
	}
	var list gen.FindingList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(list.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(list.Findings))
	}
	if list.Findings[0].Epss == nil || list.Findings[0].Epss.Score != 0.99999 {
		t.Fatalf("epss = %+v, want 0.99999", list.Findings[0].Epss)
	}

	planResp := ts.do(t, http.MethodGet, "/api/assets/"+strconv.FormatInt(asset.ID, 10)+"/fix-plan", withCookie(cookie))
	if planResp.StatusCode != http.StatusOK {
		t.Fatalf("fix plan status = %d", planResp.StatusCode)
	}
	var plan gen.FixPlan
	if err := json.NewDecoder(planResp.Body).Decode(&plan); err != nil {
		t.Fatalf("decode fix plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].MaxEpss == nil {
		t.Fatalf("fix plan steps = %+v, want one step with max_epss", plan.Steps)
	}
	if plan.Steps[0].MaxEpss.Score != 0.99999 {
		t.Errorf("max_epss = %+v, want 0.99999", plan.Steps[0].MaxEpss)
	}
}
