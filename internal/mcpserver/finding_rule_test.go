package mcpserver_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/store"
)

func TestFindingRuleLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/rules", "acme/rules")
	build := func(kind findings.Type, rule, location string) findings.Finding {
		f := newFinding(asset.ID, kind, rule, findings.SeverityHigh, rule)
		f.Location = location
		f.Fingerprint = findings.Fingerprint(asset.ID, f)
		return f
	}
	seedScan(t, db, asset.ID, time.Now(),
		build(findings.TypeMisconfig, "DS001", "tests/a/Dockerfile"),
		build(findings.TypeMisconfig, "DS001", "src/Dockerfile"),
		build(findings.TypeSecret, "generic-key", "tests/key.txt"),
		build(findings.TypeMalware, "MAL-1", "tests/evil.js"),
	)

	service := newAssetsService(t, db)
	session := newSession(t, mcpserver.Config{Assets: service, Reports: newReportsService(t, db)})
	ignored := func() int {
		t.Helper()
		return call[decisionList](t, session, "list_findings", map[string]any{"asset_id": asset.ID, "status": "ignored"}).Data.Total
	}

	// An agent's proposal closes nothing until the user approves it.
	proposal := map[string]any{
		"asset_id": asset.ID, "path_glob": "tests/*", "state": "false_positive", "reason": "fixtures",
	}
	proposed := call[struct {
		ProposalID int64  `json:"proposal_id"`
		Status     string `json:"status"`
	}](t, session, "propose_finding_rule", proposal)
	if proposed.Status != "proposed" || ignored() != 0 {
		t.Fatalf("proposal = %+v, ignored = %d", proposed, ignored())
	}
	for _, kind := range []string{"secret", "malware"} {
		refused := map[string]any{"asset_id": asset.ID, "finding_type": kind, "state": "ignored", "reason": "noise"}
		if text := callError(t, session, "propose_finding_rule", refused); !strings.Contains(text, "cannot propose") {
			t.Errorf("%s proposal error = %q", kind, text)
		}
	}

	// Approved, it closes the path match but neither the secret nor malware.
	if err := service.ApproveFindingRule(ctx, proposed.ProposalID); err != nil {
		t.Fatal(err)
	}
	if got := ignored(); got != 1 {
		t.Fatalf("ignored after approval = %d, want 1", got)
	}

	// The rule covers a finding that first appears in a later scan.
	seedScan(t, db, asset.ID, time.Now(),
		build(findings.TypeMisconfig, "DS001", "tests/a/Dockerfile"),
		build(findings.TypeMisconfig, "DS002", "tests/b/Dockerfile"),
	)
	if got := ignored(); got != 2 {
		t.Fatalf("ignored after rescan = %d, want 2", got)
	}

	// Removing the rule reopens what it closed.
	if err := service.DeleteFindingRule(ctx, proposed.ProposalID); err != nil {
		t.Fatal(err)
	}
	if got := ignored(); got != 0 {
		t.Fatalf("ignored after delete = %d, want 0", got)
	}
}

func TestSecretNeedsARuleThatNamesTheType(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/secret", "acme/secret")
	secret := newFinding(asset.ID, findings.TypeSecret, "generic-key", findings.SeverityHigh, "key")
	seedScan(t, db, asset.ID, time.Now(), secret)
	service := newAssetsService(t, db)

	input := assets.FindingRuleInput{RuleID: "generic-key", State: store.FindingStateFalsePositive, Reason: "sample"}
	if _, err := service.CreateFindingRule(ctx, input); err != nil {
		t.Fatal(err)
	}
	rules, err := service.FindingRules(ctx)
	if err != nil || rules[0].Matched != 0 {
		t.Fatalf("untyped rule matched = %+v, err = %v", rules, err)
	}
	input.FindingType = "secret"
	if _, err := service.CreateFindingRule(ctx, input); err != nil {
		t.Fatal(err)
	}
	rules, err = service.FindingRules(ctx)
	if err != nil || rules[0].Matched != 1 {
		t.Fatalf("typed rule matched = %+v, err = %v", rules, err)
	}
}

func TestExpiredDecisionDoesNotBlockARule(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/expired", "acme/expired")
	finding := newFinding(asset.ID, findings.TypeMisconfig, "DS001", findings.SeverityHigh, "root user")
	seedScan(t, db, asset.ID, time.Now(), finding)
	service := newAssetsService(t, db)

	// An expired decision gives way to the rule.
	if _, err := db.ExecContext(ctx, `INSERT INTO finding_states (asset_id, fingerprint, state, reason, expires_at, decided_by)
		SELECT asset_id, fingerprint, 'ignored', 'for now', '2020-01-01T00:00:00.000Z', 'user' FROM findings`); err != nil {
		t.Fatal(err)
	}
	input := assets.FindingRuleInput{RuleID: "DS001", State: store.FindingStateIgnored, Reason: "accepted"}
	if _, err := service.CreateFindingRule(ctx, input); err != nil {
		t.Fatal(err)
	}
	rules, err := service.FindingRules(ctx)
	if err != nil || rules[0].Matched != 1 {
		t.Fatalf("rules = %+v, err = %v", rules, err)
	}
}
