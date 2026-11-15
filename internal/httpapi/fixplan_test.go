package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/store"
)

// fixPlanFinding builds one open vulnerability finding of an npm package.
func fixPlanFinding(assetID int64, ruleID, pkg, installed, fixed string, severity findings.Severity) findings.Finding {
	finding := findings.Finding{
		AssetID:        assetID,
		Type:           findings.TypeVulnerability,
		RuleID:         ruleID,
		Severity:       severity,
		Title:          "example finding " + ruleID,
		PackageName:    pkg,
		PackageVersion: installed,
		FixedVersion:   fixed,
		Ecosystem:      "npm",
		Scanner:        "trivy",
		Occurrences:    1,
	}
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// decodeFixPlan decodes a FixPlan response.
func decodeFixPlan(t *testing.T, body []byte) gen.FixPlan {
	t.Helper()

	var plan gen.FixPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode fix plan %q: %v", body, err)
	}
	return plan
}

// TestGetAssetFixPlan is the Done-when fixture through the real server: several
// CVEs in one package become one step with the right version and counts, and a
// finding without a fix is listed separately.
func TestGetAssetFixPlan(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/fixplan", DisplayName: "Fixplan",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}

	lodashLow := fixPlanFinding(asset.ID, "CVE-2026-1000", "lodash", "4.17.0", "4.17.19", findings.SeverityCritical)
	lodashHigh := fixPlanFinding(asset.ID, "CVE-2026-1001", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh)
	openssl := fixPlanFinding(asset.ID, "CVE-2026-1002", "openssl", "1.1.1n", "", findings.SeverityHigh)
	// A secret and an ignored vulnerability must not reach the plan.
	secret := findings.Finding{
		AssetID: asset.ID, Type: findings.TypeSecret, RuleID: "gitleaks-key",
		Severity: findings.SeverityHigh, Title: "secret", Scanner: "gitleaks", Occurrences: 1,
	}
	secret.Fingerprint = findings.Fingerprint(asset.ID, secret)
	ignored := fixPlanFinding(asset.ID, "CVE-2026-1003", "lodash", "4.17.0", "4.17.22", findings.SeverityMedium)

	seedReportScan(t, ts.db, asset.ID, store.ScanStatusSucceeded, reportAt(10),
		lodashLow, lodashHigh, openssl, secret, ignored)
	if err := store.SetFindingState(t.Context(), ts.db, asset.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "not exploitable"); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	resp := ts.do(t, http.MethodGet, "/api/assets/"+itoa(asset.ID)+"/fix-plan", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	plan := decodeFixPlan(t, readBody(t, resp))

	if len(plan.Steps) != 1 {
		t.Fatalf("steps = %+v, want one", plan.Steps)
	}
	step := plan.Steps[0]
	if step.Ecosystem != "npm" || step.Package != "lodash" || step.TargetVersion != "4.17.21" {
		t.Errorf("step = %+v, want npm lodash upgraded to 4.17.21", step)
	}
	if step.FindingCount != 2 || len(step.FindingIds) != 2 {
		t.Errorf("step = %+v, want the two open lodash findings", step)
	}
	if step.SeverityCounts.Critical != 1 || step.SeverityCounts.High != 1 {
		t.Errorf("severity_counts = %+v, want 1 critical and 1 high", step.SeverityCounts)
	}
	if len(step.InstalledVersions) != 1 || step.InstalledVersions[0] != "4.17.0" {
		t.Errorf("installed_versions = %+v, want [4.17.0]", step.InstalledVersions)
	}

	if len(plan.NoFix) != 1 {
		t.Fatalf("no_fix = %+v, want one package", plan.NoFix)
	}
	noFix := plan.NoFix[0]
	if noFix.Package != "openssl" || noFix.FindingCount != 1 || len(noFix.FindingIds) != 1 {
		t.Errorf("no_fix = %+v, want the one openssl finding", noFix)
	}
	if noFix.SeverityCounts.High != 1 {
		t.Errorf("no_fix severity_counts = %+v, want 1 high", noFix.SeverityCounts)
	}
}

// TestGetAssetFixPlanUnknownAsset answers 404 rather than an empty plan.
func TestGetAssetFixPlanUnknownAsset(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/assets/999/fix-plan", withCookie(cookie))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	problem := readProblem(t, resp)
	if problem.Status != http.StatusNotFound {
		t.Errorf("problem = %+v, want 404", problem)
	}
}

// TestGetAssetFixPlanEmpty keeps both lists arrays, so the UI can render them
// without a null check.
func TestGetAssetFixPlanEmpty(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/empty", DisplayName: "Empty",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}

	resp := ts.do(t, http.MethodGet, "/api/assets/"+itoa(asset.ID)+"/fix-plan", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	plan := decodeFixPlan(t, readBody(t, resp))
	if plan.Steps == nil || plan.NoFix == nil {
		t.Fatalf("plan = %+v, want empty arrays", plan)
	}
}
