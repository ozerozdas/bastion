package reports_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestSnapshot seeds coverage, findings, decisions, rules and a licence policy
// with a pinned clock and asserts every section, the asset filter and that two
// snapshots serialize to the same bytes.
func TestSnapshot(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	clock := at(12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")
	gamma := seedAsset(t, db, findings.AssetKindImage, "registry/gamma", "Gamma")

	critical := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	high := newFinding(alpha.ID, findings.TypeMisconfig, "CKV_AWS_1", findings.SeverityHigh)
	medium := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium)
	low := newFinding(alpha.ID, findings.TypeOutdated, "lodash", findings.SeverityLow)

	duration := int64(1200)
	scanID, err := store.StartScan(ctx, db, alpha.ID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if err := store.SaveScanResult(ctx, db, scanID, store.ScanResult{
		Status:     store.ScanStatusSucceeded,
		FinishedAt: at(11),
		ScannerRuns: []store.ScannerRun{
			{Scanner: "trivy", ScannerVersion: "0.60.0", DBVersion: "2026-11-01", Status: "succeeded", DurationMS: &duration},
			{Scanner: "gitleaks", Status: "failed", Error: "config missing"},
		},
		Findings: []findings.Finding{critical, high, medium, low},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}
	// Gamma's newest scan failed: its findings never count, but coverage shows
	// the failure.
	seedScan(t, db, gamma.ID, store.ScanStatusFailed, at(10))

	if err := store.SetFindingState(ctx, db, alpha.ID, medium.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState(ignored): %v", err)
	}
	if err := store.SetAgentFindingStates(ctx, db, alpha.ID, []string{high.Fingerprint},
		store.FindingStateAcceptedRisk, "agent triage", nil); err != nil {
		t.Fatalf("SetAgentFindingStates: %v", err)
	}
	expiredAt := at(1)
	if err := store.SetFindingState(ctx, db, alpha.ID, critical.Fingerprint,
		store.FindingStateFalsePositive, "vendor says no", &expiredAt); err != nil {
		t.Fatalf("SetFindingState(false_positive): %v", err)
	}

	activeID, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		AssetID:   sql.NullInt64{Int64: alpha.ID, Valid: true},
		RuleID:    sql.NullString{String: "CVE-2099-9999", Valid: true},
		State:     store.FindingStateIgnored,
		Reason:    "not deployed",
		Status:    store.FindingRuleActive,
		CreatedBy: store.FindingDeciderUser,
	})
	if err != nil {
		t.Fatalf("CreateFindingRule(active): %v", err)
	}
	if _, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		AssetID:     sql.NullInt64{Int64: alpha.ID, Valid: true},
		FindingType: sql.NullString{String: "outdated", Valid: true},
		State:       store.FindingStateIgnored,
		Reason:      "suggested by an agent",
		Status:      store.FindingRuleProposed,
		CreatedBy:   store.FindingDeciderAgent,
	}); err != nil {
		t.Fatalf("CreateFindingRule(proposed): %v", err)
	}

	policies, err := licencepolicy.NewService(db)
	if err != nil {
		t.Fatalf("licencepolicy.NewService: %v", err)
	}
	if _, err := policies.Replace(ctx, nil, licencepolicy.Policy{
		Allow: []string{"BSD-3-Clause"},
		Deny:  []string{"GPL-3.0"},
	}); err != nil {
		t.Fatalf("Replace(global policy): %v", err)
	}

	snapshot, err := service.Snapshot(ctx, nil)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if !snapshot.GeneratedAt.Equal(clock) {
		t.Errorf("generated_at = %v, want %v", snapshot.GeneratedAt, clock)
	}
	if !snapshot.Scope.All || snapshot.Scope.AssetID != nil || snapshot.Scope.AssetName != "" {
		t.Errorf("scope = %+v, want the fleet scope", snapshot.Scope)
	}

	coverage := snapshot.Coverage
	if coverage.AssetsTotal != 3 || coverage.Scanned != 2 || coverage.NeverScanned != 1 || coverage.LastScanFailed != 1 {
		t.Errorf("coverage counts = %+v, want 3 total, 2 scanned, 1 never, 1 failed", coverage)
	}
	if len(coverage.Assets) != 3 {
		t.Fatalf("coverage assets = %d, want 3", len(coverage.Assets))
	}
	for i, want := range []string{"Alpha", "Beta", "Gamma"} {
		if coverage.Assets[i].DisplayName != want {
			t.Errorf("coverage asset %d = %q, want %q", i, coverage.Assets[i].DisplayName, want)
		}
	}
	alphaCoverage := coverage.Assets[0]
	if alphaCoverage.LastScan == nil {
		t.Fatal("alpha has no last scan")
	}
	if alphaCoverage.LastScan.ID != scanID || alphaCoverage.LastScan.Status != store.ScanStatusSucceeded {
		t.Errorf("alpha last scan = %+v, want id %d succeeded", alphaCoverage.LastScan, scanID)
	}
	if alphaCoverage.LastScan.FinishedAt == nil || !alphaCoverage.LastScan.FinishedAt.Equal(at(11)) {
		t.Errorf("alpha finished_at = %v, want %v", alphaCoverage.LastScan.FinishedAt, at(11))
	}
	if len(alphaCoverage.Scanners) != 2 {
		t.Fatalf("alpha scanners = %d, want 2", len(alphaCoverage.Scanners))
	}
	failedRun := alphaCoverage.Scanners[0]
	if failedRun.Name != "gitleaks" || failedRun.Status != "failed" || failedRun.Error != "config missing" {
		t.Errorf("failed scanner run = %+v", failedRun)
	}
	trivyRun := alphaCoverage.Scanners[1]
	if trivyRun.Name != "trivy" || trivyRun.Version != "0.60.0" || trivyRun.DBVersion != "2026-11-01" {
		t.Errorf("trivy scanner run = %+v", trivyRun)
	}
	if trivyRun.DurationMS == nil || *trivyRun.DurationMS != duration {
		t.Errorf("trivy duration = %v, want %d", trivyRun.DurationMS, duration)
	}
	if coverage.Assets[1].LastScan != nil || len(coverage.Assets[1].Scanners) != 0 {
		t.Errorf("beta coverage = %+v, want never scanned", coverage.Assets[1])
	}
	if coverage.Assets[2].LastScan == nil || coverage.Assets[2].LastScan.Status != store.ScanStatusFailed {
		t.Errorf("gamma coverage = %+v, want a failed last scan", coverage.Assets[2])
	}

	findingSection := snapshot.Findings
	if findingSection.Open != 2 {
		t.Errorf("open findings = %d, want 2", findingSection.Open)
	}
	wantTotal := reports.SeverityTotals{Critical: 1, Low: 1}
	if findingSection.Total != wantTotal {
		t.Errorf("findings total = %+v, want %+v", findingSection.Total, wantTotal)
	}
	if len(findingSection.Assets) != 3 {
		t.Fatalf("finding assets = %d, want 3", len(findingSection.Assets))
	}
	if got := findingSection.Assets[0]; got.Total != 2 || got.Severity != wantTotal {
		t.Errorf("alpha findings = %+v, want %+v", got, wantTotal)
	}
	if got := findingSection.Assets[1]; got.Total != 0 || got.Severity != (reports.SeverityTotals{}) {
		t.Errorf("beta findings = %+v, want zero", got)
	}

	sla := snapshot.SLA
	if sla.Thresholds != (reports.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180}) {
		t.Errorf("sla thresholds = %+v", sla.Thresholds)
	}
	if sla.WindowDays != reports.DefaultSLAWindowDays || sla.OpenCount != 2 {
		t.Errorf("sla = %+v, want window %d and open 2", sla, reports.DefaultSLAWindowDays)
	}
	if sla.OverdueCount != 0 || len(sla.Overdue) != 0 {
		t.Errorf("sla overdue = %+v, want none", sla.Overdue)
	}

	decisions := snapshot.Decisions
	if decisions.Total != 3 || decisions.Expired != 1 {
		t.Errorf("decisions = %d total, %d expired; want 3 and 1", decisions.Total, decisions.Expired)
	}
	wantStates := []reports.SnapshotDecisionCount{
		{Key: store.FindingStateIgnored, Count: 1},
		{Key: store.FindingStateAcceptedRisk, Count: 1},
		{Key: store.FindingStateFalsePositive, Count: 1},
	}
	if len(decisions.ByState) != len(wantStates) {
		t.Fatalf("by_state = %+v, want %+v", decisions.ByState, wantStates)
	}
	for i, want := range wantStates {
		if decisions.ByState[i] != want {
			t.Errorf("by_state[%d] = %+v, want %+v", i, decisions.ByState[i], want)
		}
	}
	wantDeciders := []reports.SnapshotDecisionCount{
		{Key: store.FindingDeciderUser, Count: 2},
		{Key: store.FindingDeciderAgent, Count: 1},
	}
	for i, want := range wantDeciders {
		if decisions.ByDecidedBy[i] != want {
			t.Errorf("by_decided_by[%d] = %+v, want %+v", i, decisions.ByDecidedBy[i], want)
		}
	}
	byFingerprint := make(map[string]reports.SnapshotDecision, len(decisions.Entries))
	for _, entry := range decisions.Entries {
		byFingerprint[entry.Fingerprint] = entry
	}
	if got := byFingerprint[medium.Fingerprint]; got.State != store.FindingStateIgnored ||
		got.DecidedBy != store.FindingDeciderUser || got.Severity != "medium" ||
		got.AssetName != "Alpha" || got.Title != medium.Title || got.Expired {
		t.Errorf("ignored decision = %+v", got)
	}
	if got := byFingerprint[high.Fingerprint]; got.DecidedBy != store.FindingDeciderAgent ||
		got.State != store.FindingStateAcceptedRisk {
		t.Errorf("agent decision = %+v", got)
	}
	if got := byFingerprint[critical.Fingerprint]; !got.Expired || got.ExpiresAt == nil ||
		!got.ExpiresAt.Equal(expiredAt) {
		t.Errorf("expired decision = %+v, want expired at %v", got, expiredAt)
	}

	rules := snapshot.SuppressionRules
	if rules.ActiveCount != 1 || rules.ProposedCount != 1 || len(rules.Rules) != 1 {
		t.Fatalf("suppression rules = %+v, want 1 active and 1 proposed", rules)
	}
	rule := rules.Rules[0]
	if rule.ID != activeID || rule.AssetName != "Alpha" || rule.RuleID != "CVE-2099-9999" ||
		rule.State != store.FindingStateIgnored || rule.CreatedBy != store.FindingDeciderUser ||
		rule.Expired || rule.Matched != 0 {
		t.Errorf("active rule = %+v", rule)
	}

	policy := snapshot.LicencePolicy
	if len(policy.Global.Allow) != 1 || policy.Global.Allow[0] != "bsd-3-clause" {
		t.Errorf("global allow = %v", policy.Global.Allow)
	}
	if len(policy.Global.Deny) != 1 || policy.Global.Deny[0] != "gpl-3.0" {
		t.Errorf("global deny = %v", policy.Global.Deny)
	}
	if len(policy.Assets) != 0 {
		t.Errorf("asset policies = %+v, want none", policy.Assets)
	}

	// Two reads with the same pinned clock must produce identical bytes.
	again, err := service.Snapshot(ctx, nil)
	if err != nil {
		t.Fatalf("Snapshot (second): %v", err)
	}
	first, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal first snapshot: %v", err)
	}
	second, err := json.Marshal(again)
	if err != nil {
		t.Fatalf("marshal second snapshot: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two snapshots differ:\n%s\n%s", first, second)
	}

	// The asset filter narrows every section to Alpha.
	alphaID := alpha.ID
	scoped, err := service.Snapshot(ctx, &alphaID)
	if err != nil {
		t.Fatalf("Snapshot(alpha): %v", err)
	}
	if scoped.Scope.All || scoped.Scope.AssetID == nil || *scoped.Scope.AssetID != alpha.ID ||
		scoped.Scope.AssetName != "Alpha" {
		t.Errorf("scoped scope = %+v", scoped.Scope)
	}
	if scoped.Coverage.AssetsTotal != 1 || len(scoped.Coverage.Assets) != 1 ||
		scoped.Coverage.Assets[0].DisplayName != "Alpha" {
		t.Errorf("scoped coverage = %+v", scoped.Coverage)
	}
	if scoped.Findings.Open != 2 || len(scoped.Findings.Assets) != 1 || scoped.Findings.Assets[0].Total != 2 {
		t.Errorf("scoped findings = %+v", scoped.Findings)
	}
	if scoped.Decisions.Total != 3 || len(scoped.Decisions.Entries) != 3 {
		t.Errorf("scoped decisions = %+v", scoped.Decisions)
	}

	betaID := beta.ID
	betaSnapshot, err := service.Snapshot(ctx, &betaID)
	if err != nil {
		t.Fatalf("Snapshot(beta): %v", err)
	}
	if betaSnapshot.Coverage.AssetsTotal != 1 || betaSnapshot.Coverage.NeverScanned != 1 {
		t.Errorf("beta coverage = %+v, want one unscanned asset", betaSnapshot.Coverage)
	}
	if betaSnapshot.Findings.Open != 0 || betaSnapshot.Findings.Total != (reports.SeverityTotals{}) {
		t.Errorf("beta findings = %+v, want none", betaSnapshot.Findings)
	}
	if betaSnapshot.Decisions.Total != 0 || len(betaSnapshot.Decisions.Entries) != 0 {
		t.Errorf("beta decisions = %+v, want none", betaSnapshot.Decisions)
	}
}

// TestSnapshotScopeFiltersRulesAndSLA seeds two assets with an overdue
// finding each, a global suppression rule and one rule per asset, then asserts
// that a scoped snapshot keeps only the global and that asset's rules and only
// that asset's overdue entries, with the counts following the filter.
func TestSnapshotScopeFiltersRulesAndSLA(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	clock := at(12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/beta", "Beta")

	// Both scans finished well before the clock, so each critical finding is
	// past the 7-day critical threshold.
	oldScan := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	alphaFinding := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-0100", findings.SeverityCritical)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, oldScan, alphaFinding)
	betaFinding := newFinding(beta.ID, findings.TypeVulnerability, "CVE-2026-0200", findings.SeverityCritical)
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, oldScan, betaFinding)

	globalRule, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		RuleID:    sql.NullString{String: "CVE-2099-0001", Valid: true},
		State:     store.FindingStateIgnored,
		Reason:    "global policy",
		Status:    store.FindingRuleActive,
		CreatedBy: store.FindingDeciderUser,
	})
	if err != nil {
		t.Fatalf("CreateFindingRule(global): %v", err)
	}
	alphaRule, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		AssetID:   sql.NullInt64{Int64: alpha.ID, Valid: true},
		RuleID:    sql.NullString{String: "CVE-2099-0002", Valid: true},
		State:     store.FindingStateIgnored,
		Reason:    "alpha only",
		Status:    store.FindingRuleActive,
		CreatedBy: store.FindingDeciderUser,
	})
	if err != nil {
		t.Fatalf("CreateFindingRule(alpha): %v", err)
	}
	betaRule, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		AssetID:   sql.NullInt64{Int64: beta.ID, Valid: true},
		RuleID:    sql.NullString{String: "CVE-2099-0003", Valid: true},
		State:     store.FindingStateIgnored,
		Reason:    "beta only",
		Status:    store.FindingRuleActive,
		CreatedBy: store.FindingDeciderUser,
	})
	if err != nil {
		t.Fatalf("CreateFindingRule(beta): %v", err)
	}
	if _, err := store.CreateFindingRule(ctx, db, sqlcdb.CreateFindingRuleParams{
		AssetID:     sql.NullInt64{Int64: beta.ID, Valid: true},
		FindingType: sql.NullString{String: "vulnerability", Valid: true},
		State:       store.FindingStateIgnored,
		Reason:      "beta proposal",
		Status:      store.FindingRuleProposed,
		CreatedBy:   store.FindingDeciderAgent,
	}); err != nil {
		t.Fatalf("CreateFindingRule(beta proposal): %v", err)
	}

	fleet, err := service.Snapshot(ctx, nil)
	if err != nil {
		t.Fatalf("Snapshot(fleet): %v", err)
	}
	if fleet.SLA.OpenCount != 2 || fleet.SLA.OverdueCount != 2 || len(fleet.SLA.Overdue) != 2 {
		t.Errorf("fleet sla = %+v, want 2 open and 2 overdue", fleet.SLA)
	}
	if fleet.SuppressionRules.ActiveCount != 3 || fleet.SuppressionRules.ProposedCount != 1 ||
		len(fleet.SuppressionRules.Rules) != 3 {
		t.Errorf("fleet rules = %+v, want 3 active and 1 proposed", fleet.SuppressionRules)
	}

	alphaID := alpha.ID
	scoped, err := service.Snapshot(ctx, &alphaID)
	if err != nil {
		t.Fatalf("Snapshot(alpha): %v", err)
	}
	if scoped.SLA.OpenCount != 1 || scoped.SLA.OverdueCount != 1 || len(scoped.SLA.Overdue) != 1 {
		t.Fatalf("scoped sla = %+v, want 1 open and 1 overdue", scoped.SLA)
	}
	if overdue := scoped.SLA.Overdue[0]; overdue.AssetID != alpha.ID || overdue.FindingID == 0 {
		t.Errorf("scoped overdue = %+v, want alpha's finding", overdue)
	}

	rules := scoped.SuppressionRules
	if rules.ActiveCount != 2 || rules.ProposedCount != 0 || len(rules.Rules) != 2 {
		t.Fatalf("scoped rules = %+v, want the global and alpha rules only", rules)
	}
	seen := make(map[int64]bool, len(rules.Rules))
	for _, rule := range rules.Rules {
		if rule.AssetID != nil && *rule.AssetID != alpha.ID {
			t.Errorf("scoped rules carry asset %d, want global or alpha", *rule.AssetID)
		}
		seen[rule.ID] = true
	}
	if !seen[globalRule] || !seen[alphaRule] {
		t.Errorf("scoped rules ids = %v, want the global rule %d and alpha rule %d", seen, globalRule, alphaRule)
	}
	if seen[betaRule] {
		t.Errorf("scoped rules include beta's rule %d", betaRule)
	}
}

// TestSnapshotEmpty checks an empty database serializes empty slices, not
// nulls, so a renderer can iterate every section unconditionally.
func TestSnapshotEmpty(t *testing.T) {
	db := openTestDB(t)
	clock := at(12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	snapshot, err := service.Snapshot(context.Background(), nil)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Coverage.AssetsTotal != 0 || len(snapshot.Coverage.Assets) != 0 {
		t.Errorf("coverage = %+v, want empty", snapshot.Coverage)
	}
	if len(snapshot.Findings.Assets) != 0 || snapshot.Findings.Open != 0 {
		t.Errorf("findings = %+v, want empty", snapshot.Findings)
	}
	if len(snapshot.SLA.Overdue) != 0 || len(snapshot.Decisions.Entries) != 0 {
		t.Errorf("sla/decisions not empty: %+v %+v", snapshot.SLA, snapshot.Decisions)
	}
	if snapshot.Decisions.Total != 0 || len(snapshot.SuppressionRules.Rules) != 0 {
		t.Errorf("decisions/rules not empty: %+v %+v", snapshot.Decisions, snapshot.SuppressionRules)
	}
	if len(snapshot.LicencePolicy.Assets) != 0 {
		t.Errorf("licence asset policies = %+v, want empty", snapshot.LicencePolicy.Assets)
	}

	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(payload)
	// coverage.assets, findings.assets and licence_policy.assets, plus the
	// other sections' slices, must all be [] rather than null.
	if count := strings.Count(text, `"assets":[]`); count < 3 {
		t.Errorf("assets slices = %d in %s, want at least 3 empty arrays", count, text)
	}
	for _, fragment := range []string{
		`"overdue":[]`,
		`"entries":[]`,
		`"rules":[]`,
		`"allow":[]`,
		`"deny":[]`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("payload is missing %s: %s", fragment, text)
		}
	}
}
