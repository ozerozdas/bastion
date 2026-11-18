package mcpserver_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/store"
)

type decisionFinding struct {
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	DecidedBy   string `json:"decided_by"`
}

type decisionList struct {
	Data struct {
		Findings []decisionFinding `json:"findings"`
		Total    int               `json:"total"`
	} `json:"data"`
}

func TestAgentFindingDecisions(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/api", "acme/api")
	noise := newFinding(asset.ID, findings.TypeMisconfig, "DS001", findings.SeverityLow, "noise")
	userOwned := newFinding(asset.ID, findings.TypeMisconfig, "DS002", findings.SeverityLow, "user owned")
	secret := newFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh, "secret")
	malware := newFinding(asset.ID, findings.TypeMalware, "MAL-1", findings.SeverityCritical, "malware")
	seedScan(t, db, asset.ID, time.Now(), noise, userOwned, secret, malware)
	if err := store.SetFindingState(context.Background(), db, asset.ID, userOwned.Fingerprint,
		store.FindingStateAcceptedRisk, "the user decided", nil); err != nil {
		t.Fatal(err)
	}

	session := newSession(t, mcpserver.Config{Assets: newAssetsService(t, db), Reports: newReportsService(t, db)})
	args := func(fingerprints ...string) map[string]any {
		return map[string]any{
			"asset_id": asset.ID, "fingerprints": fingerprints,
			"state": "false_positive", "reason": "test fixture",
		}
	}

	// Refused batches write nothing, including their allowed members.
	for _, refused := range []string{secret.Fingerprint, malware.Fingerprint, userOwned.Fingerprint} {
		if text := callError(t, session, "set_finding_state", args(noise.Fingerprint, refused)); !strings.Contains(text, "nothing was written") {
			t.Errorf("refusal = %q", text)
		}
	}
	agentOnly := map[string]any{"asset_id": asset.ID, "decided_by": "agent"}
	if got := call[decisionList](t, session, "list_findings", agentOnly); got.Data.Total != 0 {
		t.Fatalf("agent decisions after refusals = %d, want 0", got.Data.Total)
	}

	set := call[struct {
		Updated   int    `json:"updated"`
		DecidedBy string `json:"decided_by"`
	}](t, session, "set_finding_state", args(noise.Fingerprint, noise.Fingerprint))
	if set.Updated != 1 || set.DecidedBy != "agent" {
		t.Fatalf("set = %+v", set)
	}
	got := call[decisionList](t, session, "list_findings", agentOnly)
	if got.Data.Total != 1 || got.Data.Findings[0].Status != "ignored" || got.Data.Findings[0].DecidedBy != "agent" {
		t.Fatalf("agent decisions = %+v", got.Data)
	}

	// The user's decision stays, and the agent can undo only its own.
	clearArgs := func(fingerprints ...string) map[string]any {
		return map[string]any{"asset_id": asset.ID, "fingerprints": fingerprints}
	}
	if text := callError(t, session, "clear_finding_state", clearArgs(noise.Fingerprint, userOwned.Fingerprint)); !strings.Contains(text, "user's decision") {
		t.Errorf("clear refusal = %q", text)
	}
	cleared := call[struct {
		Cleared int `json:"cleared"`
	}](t, session, "clear_finding_state", clearArgs(noise.Fingerprint))
	if cleared.Cleared != 1 {
		t.Fatalf("cleared = %d, want 1", cleared.Cleared)
	}
	userOnly := map[string]any{"asset_id": asset.ID, "decided_by": "user", "status": "ignored"}
	if got := call[decisionList](t, session, "list_findings", userOnly); got.Data.Total != 1 {
		t.Fatalf("user decisions = %d, want 1", got.Data.Total)
	}
}

func TestUserDecisionTakesOverAnAgentDecision(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/web", "acme/web")
	finding := newFinding(asset.ID, findings.TypeMisconfig, "DS003", findings.SeverityLow, "noise")
	seedScan(t, db, asset.ID, time.Now(), finding)

	ctx := context.Background()
	if err := store.SetAgentFindingStates(ctx, db, asset.ID, []string{finding.Fingerprint}, store.FindingStateIgnored, "agent", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateIgnored, "user", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClearAgentFindingStates(ctx, db, asset.ID, []string{finding.Fingerprint}); err == nil {
		t.Fatal("agent cleared a decision the user took over")
	}
}

func TestAgentMayDecideAfterTheUserDecisionExpired(t *testing.T) {
	db := openTestDB(t)
	asset := seedAsset(t, db, findings.AssetKindRepo, "acme/expired", "acme/expired")
	finding := newFinding(asset.ID, findings.TypeMisconfig, "DS004", findings.SeverityLow, "noise")
	seedScan(t, db, asset.ID, time.Now(), finding)

	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateIgnored, "user", &past); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAgentFindingStates(ctx, db, asset.ID, []string{finding.Fingerprint}, store.FindingStateIgnored, "agent", nil); err != nil {
		t.Fatalf("agent refused after expiry: %v", err)
	}
}
