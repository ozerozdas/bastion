package reports_test

import (
	"context"
	"math"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// scoreFactor returns the named factor of a step, failing the test when absent.
func scoreFactor(t *testing.T, step fixplan.Step, name string) fixplan.Factor {
	t.Helper()

	for _, factor := range step.Factors {
		if factor.Name == name {
			return factor
		}
	}
	t.Fatalf("step %s factors = %+v, want one named %q", step.Package, step.Factors, name)
	return fixplan.Factor{}
}

// fixableFinding builds one open vulnerability with a fix, so it becomes a step.
func fixableFinding(assetID int64, ruleID, pkg, installed, fixed string, severity findings.Severity) findings.Finding {
	finding := newFinding(assetID, findings.TypeVulnerability, ruleID, severity)
	finding.Ecosystem = "npm"
	finding.PackageName = pkg
	finding.PackageVersion = installed
	finding.FixedVersion = fixed
	return finding
}

// TestFixPlanScoresRepoStepsFromLatestImage proves the latest-image factor for a
// repo asset: a step whose advisory appears in a linked image's newest scan
// scores 1.5x, and steps are ordered by the resulting score.
func TestFixPlanScoresRepoStepsFromLatestImage(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	repo := seedAsset(t, db, findings.AssetKindRepo, "acme/app", "acme/app")
	image := seedAsset(t, db, findings.AssetKindImage, "registry/acme/app:1", "acme/app:1")
	if err := store.SetManualLink(ctx, db, image.ID, repo.ID); err != nil {
		t.Fatalf("SetManualLink: %v", err)
	}

	lodash := fixableFinding(repo.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical)
	minimist := fixableFinding(repo.ID, "CVE-2026-0002", "minimist", "1.2.5", "1.2.8", findings.SeverityHigh)
	seedScan(t, db, repo.ID, "succeeded", at(10), lodash, minimist)

	// The latest image carries the lodash advisory but not minimist's.
	imageLodash := fixableFinding(image.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical)
	seedScan(t, db, image.ID, "succeeded", at(11), imageLodash)

	plan, err := service.FixPlan(ctx, repo.ID)
	if err != nil {
		t.Fatalf("FixPlan: %v", err)
	}
	if len(plan.Steps) != 2 {
		t.Fatalf("steps = %+v, want two", plan.Steps)
	}

	if plan.Steps[0].Package != "lodash" {
		t.Fatalf("first step = %+v, want lodash (15 > 7)", plan.Steps[0])
	}
	if got := scoreFactor(t, plan.Steps[0], fixplan.FactorLatestImage); got.Value != 1.5 || got.Detail != "in latest image" {
		t.Errorf("lodash latest image = %+v, want 1.5x in latest image", got)
	}
	if want := 10 * 1.5; plan.Steps[0].Score != want {
		t.Errorf("lodash score = %v, want %v", plan.Steps[0].Score, want)
	}

	if got := scoreFactor(t, plan.Steps[1], fixplan.FactorLatestImage); got.Value != 1 || got.Detail != "not in latest image" {
		t.Errorf("minimist latest image = %+v, want 1x not in latest image", got)
	}
	if got := scoreFactor(t, plan.Steps[1], fixplan.FactorEPSS); got.Value != 1 || got.Detail != "EPSS off" {
		t.Errorf("minimist epss = %+v, want EPSS off", got)
	}
	if want := 7.0; plan.Steps[1].Score != want {
		t.Errorf("minimist score = %v, want %v", plan.Steps[1].Score, want)
	}
}

// TestFixPlanScoresImageStepByNewestScan proves the latest-image factor for an
// image asset: only the newest scanned image of its repository ranks higher.
func TestFixPlanScoresImageStepByNewestScan(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	repo := seedAsset(t, db, findings.AssetKindRepo, "acme/app", "acme/app")
	older := seedAsset(t, db, findings.AssetKindImage, "registry/acme/app:old", "acme/app:old")
	newer := seedAsset(t, db, findings.AssetKindImage, "registry/acme/app:new", "acme/app:new")
	for _, image := range []findings.Asset{older, newer} {
		if err := store.SetManualLink(ctx, db, image.ID, repo.ID); err != nil {
			t.Fatalf("SetManualLink(%d): %v", image.ID, err)
		}
	}
	seedScan(t, db, older.ID, "succeeded", at(10),
		fixableFinding(older.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical))
	seedScan(t, db, newer.ID, "succeeded", at(12),
		fixableFinding(newer.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical))

	for _, tc := range []struct {
		asset  findings.Asset
		value  float64
		detail string
	}{
		{asset: newer, value: 1.5, detail: "in latest image"},
		{asset: older, value: 1, detail: "not in latest image"},
	} {
		plan, err := service.FixPlan(ctx, tc.asset.ID)
		if err != nil {
			t.Fatalf("FixPlan(%s): %v", tc.asset.DisplayName, err)
		}
		if len(plan.Steps) != 1 {
			t.Fatalf("%s steps = %+v, want one", tc.asset.DisplayName, plan.Steps)
		}
		factor := scoreFactor(t, plan.Steps[0], fixplan.FactorLatestImage)
		if factor.Value != tc.value || factor.Detail != tc.detail {
			t.Errorf("%s latest image = %+v, want %v and %q", tc.asset.DisplayName, factor, tc.value, tc.detail)
		}
	}
}

// TestFixPlanScoreWithoutImageLink proves an unlinked asset reports the factor
// as absent rather than guessing one.
func TestFixPlanScoreWithoutImageLink(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/unlinked", "unlinked")
	seedScan(t, db, asset.ID, "succeeded", at(10),
		fixableFinding(asset.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical))

	plan, err := service.FixPlan(ctx, asset.ID)
	if err != nil {
		t.Fatalf("FixPlan: %v", err)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("steps = %+v, want one", plan.Steps)
	}
	factor := scoreFactor(t, plan.Steps[0], fixplan.FactorLatestImage)
	if factor.Value != 1 || factor.Detail != "no image link" {
		t.Errorf("latest image = %+v, want 1x no image link", factor)
	}
	if plan.Steps[0].Score != 10 {
		t.Errorf("score = %v, want 10", plan.Steps[0].Score)
	}
}

// TestFixPlanScoreRoundsToTheFormula keeps the float math honest: severity sum
// times the EPSS multiplier, no accidental rounding in the domain layer.
func TestFixPlanScoreRoundsToTheFormula(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db, reports.WithEPSS(fakeEPSS{
		"CVE-2026-0001": {Score: 0.5, Percentile: 0.9},
	}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/scored", "scored")
	seedScan(t, db, asset.ID, "succeeded", at(10),
		fixableFinding(asset.ID, "CVE-2026-0001", "lodash", "4.17.0", "4.17.21", findings.SeverityCritical))

	plan, err := service.FixPlan(ctx, asset.ID)
	if err != nil {
		t.Fatalf("FixPlan: %v", err)
	}
	// 10 × (1 + 9×0.5) = 55.
	if want := 55.0; math.Abs(plan.Steps[0].Score-want) > 1e-9 {
		t.Errorf("score = %v, want %v", plan.Steps[0].Score, want)
	}
	if got := scoreFactor(t, plan.Steps[0], fixplan.FactorEPSS); got.Value != 5.5 || got.Detail != "EPSS 0.50" {
		t.Errorf("epss = %+v, want 5.5x EPSS 0.50", got)
	}
}
