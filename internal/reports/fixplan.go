package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// FixPlan groups one asset's open vulnerability findings into package upgrades
// (PROJECT_SPEC.md §7.2, §8 Phase 3). It reuses the findings list's "open"
// semantics: the asset's most recent succeeded scan, with any live
// finding_states decision excluded (an expired one no longer hides, #32). An
// unknown asset is ErrNotFound.
//
// Steps carry the prioritization score of #29 and are ordered by it: severity
// weight sum times the EPSS and latest-image multipliers.
func (s *Service) FixPlan(ctx context.Context, assetID int64) (fixplan.Plan, error) {
	if assetID <= 0 {
		return fixplan.Plan{}, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}

	queries := sqlcdb.New(s.db)
	asset, err := queries.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fixplan.Plan{}, fmt.Errorf("%w: asset %d", ErrNotFound, assetID)
		}
		return fixplan.Plan{}, fmt.Errorf("reports: look up asset %d: %w", assetID, err)
	}

	rows, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{
		AssetID: assetID,
		Type:    string(findings.TypeVulnerability),
		Status:  FindingStatusOpen,
		Now:     s.expiryNow(),
		Limit:   allRows,
		Offset:  0,
	})
	if err != nil {
		return fixplan.Plan{}, fmt.Errorf("reports: list findings for fix plan: %w", err)
	}

	inputs := make([]fixplan.Input, 0, len(rows))
	scores := make(map[int64]epss.Score, len(rows))
	// reach carries the scan's govulncheck answer per finding; the step folds
	// them into one state (#37).
	reach := make(map[int64]findings.Reachability, len(rows))
	// keys matches a step's findings against the linked images' latest scans:
	// rule id and package, since the fingerprint embeds the asset id.
	keys := make(map[int64]string, len(rows))
	for _, row := range rows {
		inputs = append(inputs, fixplan.Input{
			ID:             row.ID,
			Ecosystem:      row.Ecosystem.String,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			Severity:       findings.Severity(row.Severity),
		})
		if row.RuleID.String != "" && row.PackageName.String != "" {
			keys[row.ID] = vulnerabilityKey(row.RuleID.String, row.PackageName.String)
		}
		if row.Reachability.Valid {
			reach[row.ID] = findings.Reachability(row.Reachability.String)
		}
		if s.epss != nil && row.RuleID.String != "" {
			if score, ok := s.epss.Lookup(row.RuleID.String); ok {
				scores[row.ID] = score
			}
		}
	}

	plan := fixplan.Build(inputs)
	link, err := s.imageLink(ctx, queries, asset)
	if err != nil {
		return fixplan.Plan{}, err
	}
	for i := range plan.Steps {
		step := &plan.Steps[i]
		step.MaxEPSS = maxScore(step.FindingIDs, scores)
		step.Reachability = stepReachability(step.FindingIDs, reach)
		scored := fixplan.Score(*step, fixplan.ScoreOptions{
			EPSSEnabled: s.epssEnabled(),
			ImageLink:   link.forStep(asset, *step, keys),
		})
		step.Score = scored.Score
		step.Factors = scored.Factors
	}
	fixplan.SortByScore(plan.Steps)
	// Attach the pull requests bastion already opened (#47). This is best
	// effort: a GitHub failure never fails the plan read.
	s.attachPullRequests(ctx, asset, &plan)
	return plan, nil
}

// imageLink is the repo <-> image context of one fix plan (#29). For a repo
// asset keys holds the rule+package of every linked image's newest succeeded
// scan; for an image asset newestImageID is the newest scanned image of its
// repository. Both are empty when the asset has no link, and the factor is then
// omitted rather than guessed.
type imageLink struct {
	linked        bool
	keys          map[string]struct{}
	newestImageID int64
}

// imageLink reads the asset's links and the findings behind the latest-image
// factor.
func (s *Service) imageLink(ctx context.Context, queries *sqlcdb.Queries, asset sqlcdb.Asset) (imageLink, error) {
	links, err := queries.ListAssetLinks(ctx)
	if err != nil {
		return imageLink{}, fmt.Errorf("reports: list asset links: %w", err)
	}

	out := imageLink{keys: map[string]struct{}{}}
	switch asset.Kind {
	case string(findings.AssetKindRepo):
		for _, link := range links {
			if link.RepoAssetID == asset.ID {
				out.linked = true
				break
			}
		}
		if !out.linked {
			return out, nil
		}
		rows, err := queries.ListLinkedImageLatestFindingKeys(ctx, asset.ID)
		if err != nil {
			return imageLink{}, fmt.Errorf("reports: list linked image findings: %w", err)
		}
		for _, row := range rows {
			if row.RuleID.String == "" || row.PackageName.String == "" {
				continue
			}
			out.keys[vulnerabilityKey(row.RuleID.String, row.PackageName.String)] = struct{}{}
		}
	case string(findings.AssetKindImage):
		repoID := int64(0)
		for _, link := range links {
			if link.ImageAssetID == asset.ID {
				repoID, out.linked = link.RepoAssetID, true
				break
			}
		}
		if !out.linked {
			return out, nil
		}
		newest, err := queries.GetNewestLinkedImageScan(ctx, repoID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// No linked image has a succeeded scan yet.
		case err != nil:
			return imageLink{}, fmt.Errorf("reports: newest linked image scan: %w", err)
		default:
			out.newestImageID = newest.ImageAssetID
		}
	}
	return out, nil
}

// forStep maps the link context onto one step: for a repo asset, any of its
// findings matching a linked image's latest scan means the fix ships there; for
// an image asset, the step ranks higher only when the asset is the newest image
// of its repository.
func (l imageLink) forStep(asset sqlcdb.Asset, step fixplan.Step, keys map[int64]string) fixplan.ImageLink {
	if !l.linked {
		return fixplan.ImageLink{}
	}
	if asset.Kind == string(findings.AssetKindImage) {
		return fixplan.ImageLink{Linked: true, Latest: l.newestImageID == asset.ID}
	}
	for _, id := range step.FindingIDs {
		key, ok := keys[id]
		if !ok {
			continue
		}
		if _, match := l.keys[key]; match {
			return fixplan.ImageLink{Linked: true, Latest: true}
		}
	}
	return fixplan.ImageLink{Linked: true}
}

// epssEnabled reports the feed setting. A lookup that cannot answer (none, or a
// test double without the setting) counts as off, so the plan says "EPSS off"
// instead of presenting a multiplier it does not have.
func (s *Service) epssEnabled() bool {
	if state, ok := s.epss.(EPSSState); ok {
		return state.Enabled()
	}
	return false
}

// vulnerabilityKey matches one finding across assets: rule id and package are
// what two scans of the same code share.
func vulnerabilityKey(ruleID, pkg string) string {
	return ruleID + "\x00" + pkg
}

// stepReachability folds the step's findings into one state, keeping the order
// the findings were read in so the result is deterministic.
func stepReachability(ids []int64, reach map[int64]findings.Reachability) findings.Reachability {
	states := make([]findings.Reachability, 0, len(ids))
	for _, id := range ids {
		if state, ok := reach[id]; ok {
			states = append(states, state)
		}
	}
	return fixplan.AggregateReachability(states)
}

// maxScore returns the highest EPSS score among the given findings, keeping its
// percentile. It returns nil when none of them has a score.
func maxScore(ids []int64, scores map[int64]epss.Score) *epss.Score {
	var highest *epss.Score
	for _, id := range ids {
		score, ok := scores[id]
		if !ok {
			continue
		}
		if highest == nil || score.Score > highest.Score {
			value := score
			highest = &value
		}
	}
	return highest
}
