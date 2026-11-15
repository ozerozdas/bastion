// Package fixplan groups open vulnerability findings into package upgrades
// (PROJECT_SPEC.md §7.2, §8 Phase 3).
//
// One step is one upgrade that closes every finding it lists: each finding
// contributes the smallest fixed version above its installed one, and the step
// takes the highest of those, so upgrading to the target satisfies every
// advisory at once. Findings no upgrade closes — no fixed version, no installed
// version, or a fixed version that is not above the installed one — are listed
// separately instead of being guessed into a step.
package fixplan

import (
	"slices"
	"strings"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	goversion "github.com/aquasecurity/go-version/pkg/version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	"golang.org/x/mod/semver"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
)

// Input is one open vulnerability finding as the plan needs it.
type Input struct {
	ID             int64
	Ecosystem      string
	PackageName    string
	PackageVersion string
	// FixedVersion is the advisory's fixed version list as stored, which Trivy
	// writes as a comma-separated list when one advisory has several fixes
	// (for example "1.2.3, 1.3.1").
	FixedVersion string
	Severity     findings.Severity
}

// SeverityCounts is the finding count per severity inside one step.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Step is one package upgrade that closes every finding in FindingIDs.
type Step struct {
	Ecosystem string
	Package   string
	// InstalledVersions is every installed version the group's findings report,
	// sorted with the ecosystem's own ordering.
	InstalledVersions []string
	// TargetVersion is the upgrade target: the highest minimal fixed version of
	// the group.
	TargetVersion string
	// Approximate is true when no ecosystem-specific comparison decided the
	// target, so the version order is a best effort rather than authoritative.
	Approximate    bool
	FindingCount   int
	SeverityCounts SeverityCounts
	FindingIDs     []int64
	// MaxEPSS is the highest EPSS prediction among the step's findings. Nil
	// when the feed is off or scores none of them. It is filled by the caller
	// that has the feed, not by Build.
	MaxEPSS *epss.Score
	// Score is the prioritization score (#29): the severity weight sum times
	// the EPSS and latest-image multipliers. Zero until the caller that has the
	// feed and the link context assigns it with Score.
	Score float64
	// Factors explains Score, in the order it was computed.
	Factors []Factor
}

// NoFix is a package whose open findings no upgrade closes.
type NoFix struct {
	Ecosystem      string
	Package        string
	FindingCount   int
	SeverityCounts SeverityCounts
	FindingIDs     []int64
}

// Plan is everything GET /api/assets/{id}/fix-plan returns.
type Plan struct {
	Steps []Step
	NoFix []NoFix
}

// Build groups findings into steps. It is pure: the caller decides which
// findings are open, and Build only orders and groups them.
func Build(inputs []Input) Plan {
	steps := make(map[string]*stepGroup)
	noFix := make(map[string]*noFixGroup)

	for _, in := range inputs {
		key := groupKey(in.Ecosystem, in.PackageName)
		target, approximate, ok := resolveTarget(in.Ecosystem, in.PackageVersion, splitVersions(in.FixedVersion))
		if !ok {
			group := noFix[key]
			if group == nil {
				group = &noFixGroup{ecosystem: in.Ecosystem, pkg: in.PackageName}
				noFix[key] = group
			}
			group.add(in)
			continue
		}
		group := steps[key]
		if group == nil {
			group = &stepGroup{ecosystem: in.Ecosystem, pkg: in.PackageName}
			steps[key] = group
		}
		group.add(in, target, approximate)
	}

	plan := Plan{
		Steps: make([]Step, 0, len(steps)),
		NoFix: make([]NoFix, 0, len(noFix)),
	}
	for _, group := range steps {
		plan.Steps = append(plan.Steps, group.step())
	}
	for _, group := range noFix {
		plan.NoFix = append(plan.NoFix, group.noFix())
	}
	sortSteps(plan.Steps)
	sortNoFix(plan.NoFix)
	return plan
}

// stepGroup accumulates the findings of one (ecosystem, package) pair that an
// upgrade closes.
type stepGroup struct {
	ecosystem string
	pkg       string
	installed []string
	targets   []resolved
	counts    SeverityCounts
	ids       []int64
}

func (g *stepGroup) add(in Input, target string, approximate bool) {
	if in.PackageVersion != "" && !slices.Contains(g.installed, in.PackageVersion) {
		g.installed = append(g.installed, in.PackageVersion)
	}
	g.targets = append(g.targets, resolved{version: target, approximate: approximate})
	g.counts.add(in.Severity)
	g.ids = append(g.ids, in.ID)
}

func (g *stepGroup) step() Step {
	target, approximate := highestTarget(g.ecosystem, g.targets)
	sortVersions(g.ecosystem, g.installed)
	slices.Sort(g.ids)
	return Step{
		Ecosystem:         g.ecosystem,
		Package:           g.pkg,
		InstalledVersions: g.installed,
		TargetVersion:     target,
		Approximate:       approximate,
		FindingCount:      len(g.ids),
		SeverityCounts:    g.counts,
		FindingIDs:        g.ids,
	}
}

// noFixGroup accumulates the findings of one (ecosystem, package) pair that no
// upgrade closes.
type noFixGroup struct {
	ecosystem string
	pkg       string
	counts    SeverityCounts
	ids       []int64
}

func (g *noFixGroup) add(in Input) {
	g.counts.add(in.Severity)
	g.ids = append(g.ids, in.ID)
}

func (g *noFixGroup) noFix() NoFix {
	slices.Sort(g.ids)
	return NoFix{
		Ecosystem:      g.ecosystem,
		Package:        g.pkg,
		FindingCount:   len(g.ids),
		SeverityCounts: g.counts,
		FindingIDs:     g.ids,
	}
}

func (c *SeverityCounts) add(severity findings.Severity) {
	switch severity {
	case findings.SeverityCritical:
		c.Critical++
	case findings.SeverityHigh:
		c.High++
	case findings.SeverityMedium:
		c.Medium++
	case findings.SeverityLow:
		c.Low++
	default:
		c.Unknown++
	}
}

// resolved is one finding's chosen fixed version.
type resolved struct {
	version     string
	approximate bool
}

// resolveTarget picks the smallest fixed version above installed. ok is false
// when the finding names no usable fixed version, which sends it to NoFix.
//
// ponytail: an npm advisory sometimes stores a range ("&gt;=4.17.11") rather
// than a version. Its lower bound is the first fixed version, so it is used as
// the candidate; a value that still does not parse falls back to the generic
// comparison and marks the target approximate.
func resolveTarget(ecosystem, installed string, candidates []string) (target string, approximate, ok bool) {
	if installed == "" {
		return "", false, false
	}
	best := ""
	bestApproximate := false
	for _, candidate := range candidates {
		candidate = lowerBound(candidate)
		if candidate == "" {
			continue
		}
		order, exact := compareVersions(ecosystem, installed, candidate)
		if order >= 0 {
			// Not above what is installed, so it cannot be the upgrade target.
			continue
		}
		if best == "" {
			best, bestApproximate = candidate, !exact
			continue
		}
		order, exact = compareVersions(ecosystem, candidate, best)
		if order < 0 {
			best, bestApproximate = candidate, !exact
		}
	}
	if best == "" {
		return "", false, false
	}
	return best, bestApproximate, true
}

// highestTarget is the step's target: the highest of its findings' minimal
// fixed versions. approximate is true when any comparison along the way used
// the generic fallback.
func highestTarget(ecosystem string, targets []resolved) (string, bool) {
	best := targets[0]
	approximate := best.approximate
	for _, candidate := range targets[1:] {
		order, exact := compareVersions(ecosystem, candidate.version, best.version)
		if !exact {
			approximate = true
		}
		if order > 0 {
			best = candidate
		}
	}
	return best.version, approximate || best.approximate
}

// compareVersions orders a and b for one ecosystem. exact is false when the
// ecosystem's parser could not read the values and the generic fallback (or, as
// a last resort, plain text order) decided, so callers can mark the target
// approximate instead of presenting a guess as fact.
func compareVersions(ecosystem, a, b string) (order int, exact bool) {
	if order, exact = compareEcosystem(ecosystem, a, b); exact {
		return order, true
	}
	if order, err := compareGeneric(a, b); err == nil {
		return order, false
	}
	return strings.Compare(a, b), false
}

// compareEcosystem orders two versions with the ecosystem's own rules. exact is
// false when this build has no parser for the ecosystem, or its parser rejected
// one of the values.
func compareEcosystem(ecosystem, a, b string) (order int, exact bool) {
	var err error
	switch strings.ToLower(ecosystem) {
	case "npm":
		order, err = compareParsed(a, b, npm.NewVersion, func(x, y npm.Version) int { return x.Compare(y) })
	case "pypi":
		order, err = compareParsed(a, b, pep440.Parse, func(x, y pep440.Version) int { return x.Compare(y) })
	case "os-deb":
		order, err = compareParsed(a, b, deb.NewVersion, func(x, y deb.Version) int { return x.Compare(y) })
	case "os-apk":
		order, err = compareParsed(a, b, apk.NewVersion, func(x, y apk.Version) int { return x.Compare(y) })
	case "os-rpm":
		order, err = compareParsed(a, b, func(s string) (rpm.Version, error) {
			return rpm.NewVersion(s), nil
		}, func(x, y rpm.Version) int { return x.Compare(y) })
	case "go":
		if !semver.IsValid(a) || !semver.IsValid(b) {
			return 0, false
		}
		return semver.Compare(a, b), true
	default:
		return 0, false
	}
	if err != nil {
		return 0, false
	}
	return order, true
}

// compareGeneric is the semver-ish fallback for ecosystems this build has no
// parser for. It reads "1.2.3", "v1.2.3" and versions with prerelease and build
// suffixes, but not Debian-style epochs or apk revisions.
func compareGeneric(a, b string) (int, error) {
	va, err := goversion.Parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := goversion.Parse(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

func compareParsed[T any](a, b string, parse func(string) (T, error), compare func(T, T) int) (int, error) {
	va, err := parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := parse(b)
	if err != nil {
		return 0, err
	}
	return compare(va, vb), nil
}

// sortVersions orders versions with the ecosystem's comparison, falling back to
// text order for values it cannot read so the output is always deterministic.
func sortVersions(ecosystem string, versions []string) {
	slices.SortStableFunc(versions, func(a, b string) int {
		order, _ := compareVersions(ecosystem, a, b)
		if order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
}

// splitVersions splits an advisory's comma-separated fixed version list.
func splitVersions(fixed string) []string {
	parts := strings.Split(fixed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// lowerBound reads the version out of a range-shaped fixed version: ">=1.2.3"
// and ">1.2.3" name the first version that carries the fix, so the bound is the
// candidate. A plain version comes back unchanged.
func lowerBound(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	for _, prefix := range []string{">=", ">"} {
		if rest, found := strings.CutPrefix(candidate, prefix); found {
			return strings.TrimSpace(rest)
		}
	}
	return candidate
}

// groupKey is the plan's grouping key: one package in one ecosystem. The
// endpoint is per asset, so the asset is implicit.
func groupKey(ecosystem, pkg string) string {
	return strings.ToLower(ecosystem) + "\x00" + pkg
}

// sortSteps orders steps by impact: critical findings, then high, then the
// total finding count, then name. It is Build's order, before the caller has
// the EPSS and link context to score steps; SortByScore reorders once scores
// are assigned.
func sortSteps(steps []Step) {
	slices.SortStableFunc(steps, compareSteps)
}

// SortByScore orders steps by prioritization score, highest first (#29). Ties
// keep Build's impact order: critical findings, then high, then total count,
// then name.
func SortByScore(steps []Step) {
	slices.SortStableFunc(steps, func(a, b Step) int {
		switch {
		case a.Score > b.Score:
			return -1
		case a.Score < b.Score:
			return 1
		default:
			return compareSteps(a, b)
		}
	})
}

// compareSteps is the impact order Build uses and SortByScore breaks ties with.
func compareSteps(a, b Step) int {
	if a.SeverityCounts.Critical != b.SeverityCounts.Critical {
		return b.SeverityCounts.Critical - a.SeverityCounts.Critical
	}
	if a.SeverityCounts.High != b.SeverityCounts.High {
		return b.SeverityCounts.High - a.SeverityCounts.High
	}
	if a.FindingCount != b.FindingCount {
		return b.FindingCount - a.FindingCount
	}
	if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
		return c
	}
	return strings.Compare(a.Package, b.Package)
}

// sortNoFix orders the unfixable packages the same way as the steps.
func sortNoFix(list []NoFix) {
	slices.SortStableFunc(list, func(a, b NoFix) int {
		if a.SeverityCounts.Critical != b.SeverityCounts.Critical {
			return b.SeverityCounts.Critical - a.SeverityCounts.Critical
		}
		if a.SeverityCounts.High != b.SeverityCounts.High {
			return b.SeverityCounts.High - a.SeverityCounts.High
		}
		if a.FindingCount != b.FindingCount {
			return b.FindingCount - a.FindingCount
		}
		if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
			return c
		}
		return strings.Compare(a.Package, b.Package)
	})
}
