package reports

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// This file attaches the pull requests bastion opened to the fix plan (#47), so
// a reloaded page shows "PR #N open" instead of offering the same bump again.
// The GitHub check is bounded and best effort: a fix plan read never fails
// because GitHub does.

const (
	// pullRequestRefreshTimeout bounds the whole refresh, not one call, so a
	// slow GitHub cannot hold the fix plan read.
	pullRequestRefreshTimeout = 2 * time.Second
	// pullRequestRefreshLimit caps the lookups one read makes.
	pullRequestRefreshLimit = 20
	// pullRequestRefreshWorkers is how many of them run at once.
	pullRequestRefreshWorkers = 4
)

// attachPullRequests marks each step that already has a pull request and
// refreshes the recorded ones: merged shows as merged, closed-without-merge is
// deleted so the step offers the action again. Errors keep the last known state
// ("open") rather than failing the read.
func (s *Service) attachPullRequests(ctx context.Context, asset sqlcdb.Asset, plan *fixplan.Plan) {
	if asset.Kind != string(findings.AssetKindRepo) || len(plan.Steps) == 0 {
		return
	}
	records, err := sqlcdb.New(s.db).ListFixPlanPullRequests(ctx, asset.ID)
	if err != nil {
		slog.Warn("could not read the fix plan pull requests", "asset", asset.ID, "error", err)
		return
	}
	if len(records) == 0 {
		return
	}

	states := make([]fixplan.PullRequestState, len(records))
	deleted := make([]bool, len(records))
	for i := range states {
		states[i] = fixplan.PullRequestOpen
	}

	refresh := records
	if len(refresh) > pullRequestRefreshLimit {
		refresh = refresh[:pullRequestRefreshLimit]
	}
	if client, owner, name, ok := s.pullRequestReader(ctx, asset); ok {
		s.refreshPullRequests(ctx, client, owner, name, refresh, states, deleted)
	}

	byKey := make(map[string]int, len(records))
	for i, record := range records {
		if deleted[i] {
			continue
		}
		byKey[stepKey(record.Ecosystem, record.Package, record.Target)] = i
	}
	for i := range plan.Steps {
		step := &plan.Steps[i]
		index, ok := byKey[stepKey(step.Ecosystem, step.Package, step.TargetVersion)]
		if !ok {
			continue
		}
		step.PullRequest = &fixplan.PullRequest{
			Number: int(records[index].Number),
			URL:    records[index].Url,
			State:  states[index],
		}
	}

	for i, remove := range deleted {
		if !remove {
			continue
		}
		if err := sqlcdb.New(s.db).DeleteFixPlanPullRequest(ctx, records[i].ID); err != nil {
			// The step still has no pull request this read; the next one retries
			// the delete.
			slog.Warn("could not delete a closed fix plan pull request",
				"id", records[i].ID, "error", err)
		}
	}
}

// pullRequestReader builds the GitHub client the refresh needs. ok is false
// when the asset has no usable GitHub connection, in which case the recorded
// pull requests are reported as open without a lookup.
func (s *Service) pullRequestReader(ctx context.Context, asset sqlcdb.Asset) (client PullRequestClient, owner, name string, ok bool) {
	if s.newGitHub == nil || s.tokens == nil || !asset.ConnectionID.Valid {
		return nil, "", "", false
	}
	kind, err := s.tokens.ConnectionKind(ctx, asset.ConnectionID.Int64)
	if err != nil || kind != connections.KindGitHub {
		return nil, "", "", false
	}
	owner, name, err = splitRepo(asset.Ref)
	if err != nil {
		return nil, "", "", false
	}
	token, err := s.tokens.ConnectionToken(ctx, asset.ConnectionID.Int64)
	if err != nil {
		return nil, "", "", false
	}
	client, err = s.newGitHub(token)
	if err != nil {
		return nil, "", "", false
	}
	return client, owner, name, true
}

// refreshPullRequests checks the recorded pull requests concurrently, bounded
// by a worker limit and one short timeout. A failure leaves the state at open.
func (s *Service) refreshPullRequests(ctx context.Context, client PullRequestClient, owner, name string, records []sqlcdb.FixPlanPullRequest, states []fixplan.PullRequestState, deleted []bool) {
	ctx, cancel := context.WithTimeout(ctx, pullRequestRefreshTimeout)
	defer cancel()

	var wg sync.WaitGroup
	slots := make(chan struct{}, pullRequestRefreshWorkers)
	for i := range records {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}

			pr, err := client.PullRequest(ctx, owner, name, int(records[i].Number))
			if err != nil {
				return
			}
			switch {
			case pr.Merged:
				states[i] = fixplan.PullRequestMerged
			case strings.EqualFold(pr.State, "closed"):
				deleted[i] = true
			}
		}(i)
	}
	wg.Wait()
}

// stepKey matches a stored pull request with a plan step: ecosystem is
// case-insensitive, the package and target are exact.
func stepKey(ecosystem, pkg, target string) string {
	return strings.ToLower(ecosystem) + "\x00" + pkg + "\x00" + target
}
