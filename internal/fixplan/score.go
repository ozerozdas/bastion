package fixplan

import (
	"fmt"
	"strings"

	"github.com/ozerozdas/bastion/internal/findings"
)

// Severity weights are CVSS-like and only rank steps (#29): a step's severity
// factor is the sum over its findings, so three high findings (21) outrank one
// critical (10). Unknown weighs the same as low, so an unrated finding never
// disappears from the ordering.
const (
	severityWeightCritical = 10.0
	severityWeightHigh     = 7.0
	severityWeightMedium   = 4.0
	severityWeightLow      = 1.0
	severityWeightUnknown  = 1.0
)

// The multipliers. EPSS maps 0..1 onto 1..10, so a CVE whose exploitation is
// nearly certain ranks ten times its severity weight. A fix that ships in the
// latest image of the asset's repository ranks 1.5x: it is the change a
// deployment of that image actually carries.
const (
	epssBoost        = 9.0
	latestImageBoost = 1.5
)

// Reachability multipliers (#37). A vulnerable function govulncheck reaches is
// the finding a fix actually removes, so it ranks above a module-level report;
// a finding govulncheck proves uncalled ranks well below it but never vanishes.
const (
	reachableBoost = 1.5
	unreachableCut = 0.3
)

// Factor names. The API exposes these verbatim; the UI labels them.
const (
	FactorSeverity     = "severity"
	FactorEPSS         = "epss"
	FactorLatestImage  = "latest_image"
	FactorReachability = "reachability"
)

// Factor is one term of a step's score, kept so the ordering is explainable:
// severity is a weight sum, the others are multipliers.
type Factor struct {
	Name   string
	Value  float64
	Detail string
}

// ImageLink is what the asset's repository <-> image links say about a step.
type ImageLink struct {
	// Linked is false when the asset has no link at all; the latest-image
	// multiplier is then omitted (1x) and reported as "no image link".
	Linked bool
	// Latest is true when the step ships in the latest image (repo asset) or
	// when the asset is the newest scanned image of its repository (image
	// asset).
	Latest bool
}

// ScoreOptions is the context a step's score needs beyond its own findings.
type ScoreOptions struct {
	// EPSSEnabled mirrors the feed setting. When false the EPSS multiplier is
	// 1x and the factor says "EPSS off".
	EPSSEnabled bool
	// ImageLink carries the repo <-> image link context for the step.
	ImageLink ImageLink
}

// Scored is a step's prioritization score and the factors that produced it.
type Scored struct {
	Score   float64
	Factors []Factor
}

// Score computes one step's prioritization score (#29):
//
//	severity weight sum × EPSS multiplier × latest-image multiplier
//
// The severity factor sums the step's findings, so a step that closes many
// findings ranks above one that closes a single finding of the same severity.
// The EPSS multiplier uses the step's highest prediction (1 + 9×EPSS); it stays
// 1 when the feed is off or none of the step's findings is scored. The
// latest-image multiplier is 1.5 when the fix ships in the image built from the
// asset's repository, and 1 otherwise.
//
// Fix availability has no factor of its own: a step exists only when an upgrade
// closes its findings, so it always contributes 1x. Findings no upgrade closes
// are listed in Plan.NoFix, which is not scored.
//
// Score is pure: the caller supplies the EPSS setting and the link context.
func Score(step Step, opts ScoreOptions) Scored {
	severity := severityWeight(step.SeverityCounts)
	factors := make([]Factor, 0, 3)
	factors = append(factors, Factor{
		Name:   FactorSeverity,
		Value:  severity,
		Detail: severityDetail(step.SeverityCounts),
	})

	epssMultiplier := 1.0
	epssDetail := "EPSS off"
	switch {
	case !opts.EPSSEnabled:
		// The feed is off: the multiplier stays 1 and the factor says why.
	case step.MaxEPSS == nil:
		epssDetail = "no EPSS score"
	default:
		epssMultiplier = 1 + epssBoost*step.MaxEPSS.Score
		epssDetail = fmt.Sprintf("EPSS %.2f", step.MaxEPSS.Score)
	}
	factors = append(factors, Factor{Name: FactorEPSS, Value: epssMultiplier, Detail: epssDetail})

	imageMultiplier := 1.0
	imageDetail := "no image link"
	if opts.ImageLink.Linked {
		if opts.ImageLink.Latest {
			imageMultiplier = latestImageBoost
			imageDetail = "in latest image"
		} else {
			imageDetail = "not in latest image"
		}
	}
	factors = append(factors, Factor{Name: FactorLatestImage, Value: imageMultiplier, Detail: imageDetail})

	reachabilityMultiplier := 1.0
	reachabilityDetail := "no Go findings"
	switch step.Reachability {
	case findings.ReachabilityReachable:
		reachabilityMultiplier = reachableBoost
		reachabilityDetail = "reachable"
	case findings.ReachabilityUnreachable:
		reachabilityMultiplier = unreachableCut
		reachabilityDetail = "unreachable"
	case findings.ReachabilityUnknown:
		reachabilityDetail = "reachability unknown"
	}
	factors = append(factors, Factor{
		Name:   FactorReachability,
		Value:  reachabilityMultiplier,
		Detail: reachabilityDetail,
	})

	return Scored{
		Score:   severity * epssMultiplier * imageMultiplier * reachabilityMultiplier,
		Factors: factors,
	}
}

// AggregateReachability folds one step's findings into a single state (#37).
// Any reachable finding wins: the step removes a call path that is actually
// used. Otherwise an unknown finding makes the step unknown, because part of it
// is undecided; only all-unreachable is unreachable. No answer at all stays
// empty, so the score can say "no Go findings" instead of guessing.
func AggregateReachability(states []findings.Reachability) findings.Reachability {
	unknown := false
	unreachable := false
	for _, state := range states {
		switch state {
		case findings.ReachabilityReachable:
			return findings.ReachabilityReachable
		case findings.ReachabilityUnknown:
			unknown = true
		case findings.ReachabilityUnreachable:
			unreachable = true
		}
	}
	switch {
	case unknown:
		return findings.ReachabilityUnknown
	case unreachable:
		return findings.ReachabilityUnreachable
	default:
		return ""
	}
}

// severityWeight sums the step's findings on the ranking scale.
func severityWeight(counts SeverityCounts) float64 {
	return float64(counts.Critical)*severityWeightCritical +
		float64(counts.High)*severityWeightHigh +
		float64(counts.Medium)*severityWeightMedium +
		float64(counts.Low)*severityWeightLow +
		float64(counts.Unknown)*severityWeightUnknown
}

// severityDetail spells the weight sum out for the UI: "1 critical + 2 high".
func severityDetail(counts SeverityCounts) string {
	parts := make([]string, 0, 5)
	add := func(count int, label string) {
		if count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count, label))
		}
	}
	add(counts.Critical, "critical")
	add(counts.High, "high")
	add(counts.Medium, "medium")
	add(counts.Low, "low")
	add(counts.Unknown, "unknown")
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, " + ")
}
