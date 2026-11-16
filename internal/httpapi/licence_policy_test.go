package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// createLicenceAsset creates one asset for the policy fixture.
func createLicenceAsset(t *testing.T, ts *testServer, kind findings.AssetKind, ref, name string) findings.Asset {
	t.Helper()

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: kind, Ref: ref, DisplayName: name,
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(%q): %v", ref, err)
	}
	return asset
}

// putLicencePolicy stores one scope's policy and returns the response.
func putLicencePolicy(t *testing.T, ts *testServer, cookie *http.Cookie, assetID string, body string) *http.Response {
	t.Helper()

	path := "/api/licence-policy"
	if assetID != "" {
		path += "?asset_id=" + assetID
	}
	return ts.doJSON(t, http.MethodPut, path, body, cookie, true)
}

// TestLicencePolicyAllowHidesDenyRaises is the #39 acceptance fixture: an
// allow-listed licence disappears from the list, its total and the export,
// while a deny-listed one stays with a severity of at least high.
func TestLicencePolicyAllowHidesDenyRaises(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	asset := createLicenceAsset(t, ts, findings.AssetKindPath, "/tmp/licences", "Licences")
	seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(10),
		newReportFinding(asset.ID, findings.TypeLicense, "GPL-3.0", findings.SeverityLow),
		newReportFinding(asset.ID, findings.TypeLicense, "MIT", findings.SeverityLow),
		newReportFinding(asset.ID, findings.TypeLicense, "Apache-2.0", findings.SeverityMedium),
	)

	resp := putLicencePolicy(t, ts, cookie, "", `{"allow":["MIT"],"deny":["GPL-3.0"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var stored genLicencePolicy
	if err := json.Unmarshal(readBody(t, resp), &stored); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if len(stored.Allow) != 1 || stored.Allow[0] != "mit" {
		t.Errorf("allow = %v, want [mit]", stored.Allow)
	}
	if len(stored.Deny) != 1 || stored.Deny[0] != "gpl-3.0" {
		t.Errorf("deny = %v, want [gpl-3.0]", stored.Deny)
	}

	// The single list hides the allow rule and raises the deny rule to high.
	resp = ts.do(t, http.MethodGet, "/api/findings", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	list := decodeFindings(t, readBody(t, resp))
	if list.Total != 2 || len(list.Findings) != 2 {
		t.Fatalf("findings = %+v (total %d), want 2 after hiding MIT", list.Findings, list.Total)
	}
	byRule := map[string]gen.Finding{}
	for _, finding := range list.Findings {
		if finding.RuleId == nil {
			t.Fatalf("finding has no rule id: %+v", finding)
		}
		byRule[*finding.RuleId] = finding
	}
	if _, ok := byRule["MIT"]; ok {
		t.Errorf("allow-listed MIT is still listed: %+v", byRule["MIT"])
	}
	gplRow, ok := byRule["GPL-3.0"]
	if !ok {
		t.Fatalf("deny-listed GPL-3.0 is missing: %+v", byRule)
	}
	if gplRow.Severity != gen.SeverityHigh {
		t.Errorf("GPL-3.0 severity = %q, want high", gplRow.Severity)
	}
	if gplRow.LicencePolicy == nil || *gplRow.LicencePolicy != gen.Deny {
		t.Errorf("GPL-3.0 licence_policy = %v, want deny", gplRow.LicencePolicy)
	}
	if apacheRow, ok := byRule["Apache-2.0"]; !ok || apacheRow.Severity != gen.SeverityMedium {
		t.Errorf("Apache-2.0 = %+v, want an unchanged medium finding", apacheRow)
	}

	// The severity filter reads the effective severity, not the stored one.
	resp = ts.do(t, http.MethodGet, "/api/findings?severity=high", withCookie(cookie))
	high := decodeFindings(t, readBody(t, resp))
	if high.Total != 1 || len(high.Findings) != 1 || high.Findings[0].RuleId == nil || *high.Findings[0].RuleId != "GPL-3.0" {
		t.Errorf("severity=high = %+v (total %d), want only the denied licence", high.Findings, high.Total)
	}

	// The grouped view and its totals use the same filtered list.
	resp = ts.do(t, http.MethodGet, "/api/findings?view=grouped", withCookie(cookie))
	grouped := decodeFindings(t, readBody(t, resp))
	if grouped.Total != 2 || grouped.TotalFindings != 2 || len(grouped.Groups) != 2 {
		t.Errorf("grouped = %+v (total %d, findings %d), want 2 groups and 2 findings",
			grouped.Groups, grouped.Total, grouped.TotalFindings)
	}

	// The export is the list's own read model, so the allow rule is hidden there too.
	resp = ts.do(t, http.MethodGet, "/api/findings/export?format=json&view=single", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d", resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.Unmarshal(readBody(t, resp), &rows); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("export rows = %d, want 2", len(rows))
	}
	for _, row := range rows {
		if row["rule"] == "MIT" {
			t.Errorf("allow-listed MIT is in the export: %+v", row)
		}
		if row["rule"] == "GPL-3.0" && row["severity"] != "high" {
			t.Errorf("exported GPL-3.0 severity = %v, want high", row["severity"])
		}
	}

	// Dashboard counts are computed from the same policy.
	resp = ts.do(t, http.MethodGet, "/api/reports/dashboard", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.StatusCode)
	}
	var dashboard struct {
		TotalsBySeverity struct {
			High   int `json:"high"`
			Medium int `json:"medium"`
		} `json:"totals_by_severity"`
		TotalsByType struct {
			License int `json:"license"`
		} `json:"totals_by_type"`
	}
	if err := json.Unmarshal(readBody(t, resp), &dashboard); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if dashboard.TotalsBySeverity.High != 1 || dashboard.TotalsBySeverity.Medium != 1 {
		t.Errorf("dashboard severities = %+v, want high 1 and medium 1", dashboard.TotalsBySeverity)
	}
	if dashboard.TotalsByType.License != 2 {
		t.Errorf("dashboard licence count = %d, want 2", dashboard.TotalsByType.License)
	}
}

// TestLicencePolicyPerAssetOverridesGlobal proves a rule on the asset wins over
// the global rule for the same licence.
func TestLicencePolicyPerAssetOverridesGlobal(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	alpha := createLicenceAsset(t, ts, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := createLicenceAsset(t, ts, findings.AssetKindRepo, "octo/beta", "Beta")
	seedReportScan(t, ts.db, alpha.ID, store.ScanStatusSucceeded, reportAt(10),
		newReportFinding(alpha.ID, findings.TypeLicense, "GPL-3.0", findings.SeverityLow))
	seedReportScan(t, ts.db, beta.ID, store.ScanStatusSucceeded, reportAt(11),
		newReportFinding(beta.ID, findings.TypeLicense, "GPL-3.0", findings.SeverityLow))

	if resp := putLicencePolicy(t, ts, cookie, "", `{"allow":[],"deny":["GPL-3.0"]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("global PUT status = %d", resp.StatusCode)
	}
	// Alpha overrides the global deny with an allow.
	if resp := putLicencePolicy(t, ts, cookie, itoa(alpha.ID), `{"allow":["GPL-3.0"],"deny":[]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("asset PUT status = %d", resp.StatusCode)
	}

	resp := ts.do(t, http.MethodGet, "/api/findings?asset_id="+itoa(alpha.ID), withCookie(cookie))
	if list := decodeFindings(t, readBody(t, resp)); list.Total != 0 {
		t.Errorf("alpha findings = %+v (total %d), want 0", list.Findings, list.Total)
	}

	resp = ts.do(t, http.MethodGet, "/api/findings?asset_id="+itoa(beta.ID), withCookie(cookie))
	list := decodeFindings(t, readBody(t, resp))
	if list.Total != 1 || len(list.Findings) != 1 || list.Findings[0].Severity != gen.SeverityHigh {
		t.Errorf("beta findings = %+v (total %d), want the global deny at high", list.Findings, list.Total)
	}

	// The per-asset allow also hides alpha's finding from the fleet-wide list.
	resp = ts.do(t, http.MethodGet, "/api/findings", withCookie(cookie))
	all := decodeFindings(t, readBody(t, resp))
	if all.Total != 1 {
		t.Errorf("fleet findings = %+v (total %d), want only beta", all.Findings, all.Total)
	}

	// GET returns each scope separately.
	resp = ts.do(t, http.MethodGet, "/api/licence-policy?asset_id="+itoa(alpha.ID), withCookie(cookie))
	var alphaPolicy genLicencePolicy
	if err := json.Unmarshal(readBody(t, resp), &alphaPolicy); err != nil {
		t.Fatalf("decode alpha policy: %v", err)
	}
	if len(alphaPolicy.Allow) != 1 || alphaPolicy.Allow[0] != "gpl-3.0" {
		t.Errorf("alpha policy = %+v, want the allow override", alphaPolicy)
	}
	resp = ts.do(t, http.MethodGet, "/api/licence-policy", withCookie(cookie))
	var globalPolicy genLicencePolicy
	if err := json.Unmarshal(readBody(t, resp), &globalPolicy); err != nil {
		t.Fatalf("decode global policy: %v", err)
	}
	if len(globalPolicy.Deny) != 1 || globalPolicy.Deny[0] != "gpl-3.0" {
		t.Errorf("global policy = %+v, want the deny rule", globalPolicy)
	}
}

// TestLicencePolicyValidation covers the 400s the endpoint promises and the 404
// for an unknown asset.
func TestLicencePolicyValidation(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	long := strings.Repeat("a", 129)
	many := make([]string, 0, 501)
	for i := 0; i < 501; i++ {
		many = append(many, `"licence-`+itoa(int64(i))+`"`)
	}

	cases := []struct {
		name string
		body string
	}{
		{name: "empty entry", body: `{"allow":[""],"deny":[]}`},
		{name: "too long", body: `{"allow":["` + long + `"],"deny":[]}`},
		{name: "not ASCII", body: `{"allow":["MIT™"],"deny":[]}`},
		{name: "in both lists", body: `{"allow":["MIT"],"deny":["mit"]}`},
		{name: "too many entries", body: `{"allow":[` + strings.Join(many, ",") + `],"deny":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := putLicencePolicy(t, ts, cookie, "", tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
			problem := readProblem(t, resp)
			if problem.Detail == nil || *problem.Detail == "" {
				t.Errorf("problem = %+v, want a detail", problem)
			}
		})
	}

	// A rejected write left the policy untouched.
	resp := ts.do(t, http.MethodGet, "/api/licence-policy", withCookie(cookie))
	var policy genLicencePolicy
	if err := json.Unmarshal(readBody(t, resp), &policy); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if len(policy.Allow) != 0 || len(policy.Deny) != 0 {
		t.Errorf("policy after rejected writes = %+v, want empty", policy)
	}

	resp = putLicencePolicy(t, ts, cookie, "999", `{"allow":[],"deny":[]}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown asset PUT status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	readProblem(t, resp)

	resp = ts.do(t, http.MethodGet, "/api/licence-policy?asset_id=999", withCookie(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown asset GET status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	readProblem(t, resp)
}

// genLicencePolicy is the response body of both policy endpoints.
type genLicencePolicy struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}
