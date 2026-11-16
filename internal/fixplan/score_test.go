package fixplan

import (
	"math"
	"testing"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
)

// factor returns the named factor of a score, failing the test when it is
// absent.
func factor(t *testing.T, scored Scored, name string) Factor {
	t.Helper()

	for _, f := range scored.Factors {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("factors = %+v, want one named %q", scored.Factors, name)
	return Factor{}
}

// TestScoreSeverityWeights pins the weight sum and its explanation: a step's
// severity factor adds its findings, so many findings outrank one of the same
// severity.
func TestScoreSeverityWeights(t *testing.T) {
	step := Step{SeverityCounts: SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1, Unknown: 1}}
	scored := Score(step, ScoreOptions{})

	// 10 + 2*7 + 4 + 1 + 1 = 30.
	if scored.Score != 30 {
		t.Errorf("score = %v, want 30", scored.Score)
	}
	severity := factor(t, scored, FactorSeverity)
	if severity.Value != 30 {
		t.Errorf("severity = %v, want 30", severity.Value)
	}
	if severity.Detail != "1 critical + 2 high + 1 medium + 1 low + 1 unknown" {
		t.Errorf("severity detail = %q", severity.Detail)
	}
}

// TestScoreEPSS covers the multiplier with the feed off, on but unscored, and
// on with a prediction.
func TestScoreEPSS(t *testing.T) {
	step := Step{SeverityCounts: SeverityCounts{Critical: 1}}

	t.Run("feed off", func(t *testing.T) {
		scored := Score(step, ScoreOptions{EPSSEnabled: false})
		epssFactor := factor(t, scored, FactorEPSS)
		if epssFactor.Value != 1 || epssFactor.Detail != "EPSS off" {
			t.Errorf("epss = %+v, want 1x and EPSS off", epssFactor)
		}
		if scored.Score != 10 {
			t.Errorf("score = %v, want 10", scored.Score)
		}
	})

	t.Run("no score", func(t *testing.T) {
		scored := Score(step, ScoreOptions{EPSSEnabled: true})
		epssFactor := factor(t, scored, FactorEPSS)
		if epssFactor.Value != 1 || epssFactor.Detail != "no EPSS score" {
			t.Errorf("epss = %+v, want 1x and no EPSS score", epssFactor)
		}
	})

	t.Run("prediction", func(t *testing.T) {
		step := step
		step.MaxEPSS = &epss.Score{Score: 0.5, Percentile: 0.9}
		scored := Score(step, ScoreOptions{EPSSEnabled: true})
		epssFactor := factor(t, scored, FactorEPSS)
		if epssFactor.Value != 5.5 {
			t.Errorf("epss = %v, want 5.5 (1 + 9*0.5)", epssFactor.Value)
		}
		if epssFactor.Detail != "EPSS 0.50" {
			t.Errorf("epss detail = %q", epssFactor.Detail)
		}
		if scored.Score != 55 {
			t.Errorf("score = %v, want 55", scored.Score)
		}
	})
}

// TestScoreLatestImage covers the image multiplier: absent without a link, 1x
// when the step is not in the latest image, 1.5x when it is.
func TestScoreLatestImage(t *testing.T) {
	step := Step{SeverityCounts: SeverityCounts{Critical: 1}}

	cases := []struct {
		name   string
		link   ImageLink
		value  float64
		detail string
	}{
		{name: "no link", link: ImageLink{}, value: 1, detail: "no image link"},
		{name: "not latest", link: ImageLink{Linked: true}, value: 1, detail: "not in latest image"},
		{name: "latest", link: ImageLink{Linked: true, Latest: true}, value: 1.5, detail: "in latest image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scored := Score(step, ScoreOptions{ImageLink: tc.link})
			imageFactor := factor(t, scored, FactorLatestImage)
			if imageFactor.Value != tc.value || imageFactor.Detail != tc.detail {
				t.Errorf("latest image = %+v, want %v and %q", imageFactor, tc.value, tc.detail)
			}
			if want := 10 * tc.value; scored.Score != want {
				t.Errorf("score = %v, want %v", scored.Score, want)
			}
		})
	}
}

// TestScoreCombinesFactors is the formula end to end: severity × EPSS × image.
func TestScoreCombinesFactors(t *testing.T) {
	step := Step{
		SeverityCounts: SeverityCounts{Critical: 1, High: 1},
		MaxEPSS:        &epss.Score{Score: 0.99999, Percentile: 1},
	}
	scored := Score(step, ScoreOptions{
		EPSSEnabled: true,
		ImageLink:   ImageLink{Linked: true, Latest: true},
	})

	want := 17 * (1 + 9*0.99999) * 1.5
	if math.Abs(scored.Score-want) > 1e-9 {
		t.Errorf("score = %v, want %v", scored.Score, want)
	}
	if len(scored.Factors) != 4 {
		t.Fatalf("factors = %+v, want severity, epss, latest_image and reachability", scored.Factors)
	}
}

// TestSortByScoreOrdersSteps proves many findings outrank one critical finding
// once scores are assigned, and that ties keep the impact order.
func TestSortByScoreOrdersSteps(t *testing.T) {
	plan := Build([]Input{
		{ID: 1, Ecosystem: "npm", PackageName: "one-critical", PackageVersion: "1.0.0", FixedVersion: "1.0.1", Severity: findings.SeverityCritical},
		{ID: 2, Ecosystem: "npm", PackageName: "three-high", PackageVersion: "1.0.0", FixedVersion: "1.0.1", Severity: findings.SeverityHigh},
		{ID: 3, Ecosystem: "npm", PackageName: "three-high", PackageVersion: "1.0.0", FixedVersion: "1.0.1", Severity: findings.SeverityHigh},
		{ID: 4, Ecosystem: "npm", PackageName: "three-high", PackageVersion: "1.0.0", FixedVersion: "1.0.1", Severity: findings.SeverityHigh},
		// One high finding scores 7, below the single critical finding's 10.
		{ID: 5, Ecosystem: "npm", PackageName: "one-high", PackageVersion: "1.0.0", FixedVersion: "1.0.1", Severity: findings.SeverityHigh},
	})

	for i := range plan.Steps {
		scored := Score(plan.Steps[i], ScoreOptions{})
		plan.Steps[i].Score = scored.Score
		plan.Steps[i].Factors = scored.Factors
	}
	SortByScore(plan.Steps)

	if len(plan.Steps) != 3 {
		t.Fatalf("steps = %+v, want three", plan.Steps)
	}
	if plan.Steps[0].Package != "three-high" {
		t.Errorf("first step = %+v, want three-high (21 > 10)", plan.Steps[0])
	}
	if plan.Steps[1].Package != "one-critical" || plan.Steps[2].Package != "one-high" {
		t.Errorf("steps = %+v, want one-critical then one-high", plan.Steps)
	}
}

// TestSortByScoreTieBreak keeps the impact order when scores are equal: more
// critical findings, then high, then total count.
func TestSortByScoreTieBreak(t *testing.T) {
	steps := []Step{
		{Package: "a", Score: 10, SeverityCounts: SeverityCounts{High: 1}, FindingCount: 1},
		{Package: "b", Score: 10, SeverityCounts: SeverityCounts{Critical: 1}, FindingCount: 1},
		{Package: "c", Score: 10, SeverityCounts: SeverityCounts{High: 2}, FindingCount: 2},
	}
	SortByScore(steps)
	got := []string{steps[0].Package, steps[1].Package, steps[2].Package}
	want := []string{"b", "c", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// TestScoreReachability covers the #37 multiplier and its step aggregation: a
// reachable call outranks a module-level report, which is cut but never
// dropped, and no Go finding leaves the score unchanged.
func TestScoreReachability(t *testing.T) {
	step := Step{SeverityCounts: SeverityCounts{Critical: 1}}

	tests := []struct {
		state  findings.Reachability
		value  float64
		detail string
		score  float64
	}{
		{findings.ReachabilityReachable, 1.5, "reachable", 15},
		{findings.ReachabilityUnreachable, 0.3, "unreachable", 3},
		{findings.ReachabilityUnknown, 1, "reachability unknown", 10},
		{"", 1, "no Go findings", 10},
	}
	for _, tt := range tests {
		step.Reachability = tt.state
		scored := Score(step, ScoreOptions{})
		got := factor(t, scored, FactorReachability)
		if got.Value != tt.value || got.Detail != tt.detail {
			t.Errorf("%q factor = %+v, want %v and %q", tt.state, got, tt.value, tt.detail)
		}
		if scored.Score != tt.score {
			t.Errorf("%q score = %v, want %v", tt.state, scored.Score, tt.score)
		}
	}

	if got := AggregateReachability([]findings.Reachability{
		findings.ReachabilityUnreachable, findings.ReachabilityReachable,
	}); got != findings.ReachabilityReachable {
		t.Errorf("aggregate = %q, want reachable", got)
	}
	if got := AggregateReachability([]findings.Reachability{
		findings.ReachabilityUnreachable, findings.ReachabilityUnknown,
	}); got != findings.ReachabilityUnknown {
		t.Errorf("aggregate = %q, want unknown", got)
	}
	if got := AggregateReachability(nil); got != "" {
		t.Errorf("aggregate of nothing = %q, want empty", got)
	}
}
