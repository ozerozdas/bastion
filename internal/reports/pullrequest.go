package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// This file opens a manifest-only pull request for one fix plan step (#47):
// bastion edits go.mod or package.json through the GitHub REST API on a new
// branch and opens the pull request. It never clones the repository, never runs
// a package manager and never touches the lockfile.

var (
	// ErrPullRequestUnavailable means the server was built without a GitHub
	// client factory or a token source.
	ErrPullRequestUnavailable = errors.New("reports: pull requests are not configured; start bastion serve with its database")
	// ErrPullRequestUnsupported means the asset cannot get a pull request: it
	// is not a repository, has no GitHub connection, or its ecosystem has no
	// supported manifest.
	ErrPullRequestUnsupported = errors.New("reports: this asset cannot get a pull request")
	// ErrPullRequestStep means the request names no step of the asset's current
	// plan with that exact target.
	ErrPullRequestStep = errors.New("reports: no fix plan step matches")
	// ErrTransitiveDependency means the package has no manifest entry, so no
	// branch or pull request was created.
	ErrTransitiveDependency = errors.New("reports: transitive dependency; bump its parent")
	// ErrPullRequestConflict means the branch already exists.
	ErrPullRequestConflict = errors.New("reports: the branch already exists")
)

// validTarget is the version shape a manifest can hold: letters, digits, dot,
// plus, underscore and hyphen, starting with an alphanumeric. It keeps a value
// like "v1.0.1\n\nrequire evil" or `4.17.21", "evil": "1.0.0` out of the file
// and out of the commit message.
var validTarget = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)

// PullRequestConflict reports an existing branch. URL and Number name the open
// pull request for it; URL is empty when there is none.
type PullRequestConflict struct {
	Branch string
	Number int
	URL    string
}

// Error implements error. Without a pull request the detail tells the user how
// to retry, since bastion never force-pushes a branch it does not own.
func (e *PullRequestConflict) Error() string {
	if e.URL != "" {
		return fmt.Sprintf("branch %q already has an open pull request: %s", e.Branch, e.URL)
	}
	return fmt.Sprintf("branch %q already exists on GitHub; delete it to retry", e.Branch)
}

// Is makes errors.Is(err, ErrPullRequestConflict) true.
func (*PullRequestConflict) Is(target error) bool { return target == ErrPullRequestConflict }

// PullRequestClient is the GitHub REST surface a manifest pull request needs.
// *github.Client implements it; tests inject a fake or a client pointed at an
// httptest server.
type PullRequestClient interface {
	Repo(ctx context.Context, owner, name string) (github.Repo, error)
	ResolveSHA(ctx context.Context, owner, name, ref string) (string, error)
	RefSHA(ctx context.Context, owner, name, branch string) (string, bool, error)
	File(ctx context.Context, owner, name, path, ref string) (github.File, error)
	CreateRef(ctx context.Context, owner, name, branch, sha string) error
	DeleteRef(ctx context.Context, owner, name, branch string) error
	PullRequest(ctx context.Context, owner, name string, number int) (github.PullRequest, error)
	PutFile(ctx context.Context, in github.PutFileInput) (github.File, error)
	CreatePullRequest(ctx context.Context, in github.PullRequestInput) (github.PullRequest, error)
	PullRequestsForHead(ctx context.Context, owner, name, head string) ([]github.PullRequest, error)
}

// PullRequestClientFactory builds a client for a token. The token is only ever
// passed in memory.
type PullRequestClientFactory func(token string) (PullRequestClient, error)

// GitTokenSource resolves a connection's GitHub token. *connections.Service
// implements it.
type GitTokenSource interface {
	ConnectionToken(ctx context.Context, id int64) (string, error)
	// ConnectionKind proves the asset's connection is a GitHub one before its
	// token is used.
	ConnectionKind(ctx context.Context, id int64) (string, error)
}

// WithGitHub wires the credential lookup and client factory that back
// POST /api/assets/{id}/fix-plan/pull-request.
func WithGitHub(factory PullRequestClientFactory, tokens GitTokenSource) Option {
	return func(s *Service) {
		if factory != nil {
			s.newGitHub = factory
		}
		if tokens != nil {
			s.tokens = tokens
		}
	}
}

// PullRequestInput is one POST /api/assets/{id}/fix-plan/pull-request body.
type PullRequestInput struct {
	Ecosystem string
	Package   string
	Target    string
	Confirm   bool
}

// PullRequestResult is the pull request a confirmed step opened.
type PullRequestResult struct {
	URL      string
	Number   int
	Branch   string
	Manifest string
}

// pullRequestStep is one finding of the step, as the pull request body lists it.
type pullRequestStep struct {
	RuleID   string
	Severity string
}

// OpenFixPlanPullRequest bumps one fix plan step in the asset's manifest and
// opens a pull request against the default branch. Everything is recomputed
// here: the caller's target only selects a step of the plan bastion builds from
// the asset's open findings, so a stale or forged version is refused. Nothing is
// written to GitHub unless Confirm is true.
func (s *Service) OpenFixPlanPullRequest(ctx context.Context, assetID int64, in PullRequestInput) (PullRequestResult, error) {
	if s.newGitHub == nil || s.tokens == nil {
		return PullRequestResult{}, ErrPullRequestUnavailable
	}
	if assetID <= 0 {
		return PullRequestResult{}, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	ecosystem := strings.ToLower(strings.TrimSpace(in.Ecosystem))
	pkg := strings.TrimSpace(in.Package)
	target := strings.TrimSpace(in.Target)
	if !in.Confirm {
		return PullRequestResult{}, fmt.Errorf("%w: confirm must be true", ErrInvalid)
	}
	if pkg == "" || target == "" || ecosystem == "" {
		return PullRequestResult{}, fmt.Errorf("%w: ecosystem, package and target are required", ErrInvalid)
	}
	if ecosystem != "go" && ecosystem != "npm" {
		return PullRequestResult{}, fmt.Errorf("%w: ecosystem %q (only go and npm manifests are supported)", ErrPullRequestUnsupported, ecosystem)
	}
	if !validTarget.MatchString(target) {
		return PullRequestResult{}, fmt.Errorf("%w: target %q is not a version", ErrPullRequestUnsupported, target)
	}

	queries := sqlcdb.New(s.db)
	asset, err := queries.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PullRequestResult{}, fmt.Errorf("%w: asset %d", ErrNotFound, assetID)
		}
		return PullRequestResult{}, fmt.Errorf("reports: look up asset %d: %w", assetID, err)
	}
	if asset.Kind != string(findings.AssetKindRepo) {
		return PullRequestResult{}, fmt.Errorf("%w: asset %d is a %s, not a repository", ErrPullRequestUnsupported, assetID, asset.Kind)
	}
	if !asset.ConnectionID.Valid {
		return PullRequestResult{}, fmt.Errorf("%w: asset %d has no GitHub connection", ErrPullRequestUnsupported, assetID)
	}
	kind, err := s.tokens.ConnectionKind(ctx, asset.ConnectionID.Int64)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("reports: resolve the connection kind of asset %d: %w", assetID, err)
	}
	if kind != connections.KindGitHub {
		return PullRequestResult{}, fmt.Errorf("%w: connection %d is %s, not github", ErrPullRequestUnsupported, asset.ConnectionID.Int64, kind)
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
		return PullRequestResult{}, fmt.Errorf("reports: list findings for the pull request: %w", err)
	}

	step, ok := matchStep(rows, ecosystem, pkg, target)
	if !ok {
		return PullRequestResult{}, fmt.Errorf("%w: %s %s to %s is not in the asset's current fix plan", ErrPullRequestStep, ecosystem, pkg, target)
	}

	manifest, findings, err := stepManifest(ecosystem, step, rows)
	if err != nil {
		return PullRequestResult{}, err
	}

	token, err := s.tokens.ConnectionToken(ctx, asset.ConnectionID.Int64)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("reports: resolve the GitHub token of asset %d: %w", assetID, err)
	}
	client, err := s.newGitHub(token)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}

	owner, name, err := splitRepo(asset.Ref)
	if err != nil {
		return PullRequestResult{}, err
	}

	result, err := s.openGitHubPullRequest(ctx, client, owner, name, pullRequestPlan{
		Package:   pkg,
		Target:    target,
		Manifest:  manifest,
		Findings:  findings,
		Ecosystem: ecosystem,
	})
	if err != nil {
		// A 409 that names an open pull request is the same fact a successful
		// create records: the step is already bumped, so remember it.
		var conflict *PullRequestConflict
		if errors.As(err, &conflict) && conflict.URL != "" && conflict.Number > 0 {
			s.recordPullRequest(ctx, assetID, ecosystem, pkg, target, conflict.Branch, conflict.Number, conflict.URL, manifest)
		}
		return PullRequestResult{}, err
	}
	s.recordPullRequest(ctx, assetID, ecosystem, pkg, target, result.Branch, result.Number, result.URL, result.Manifest)
	return result, nil
}

// recordPullRequest stores the pull request a step now has, so a reloaded page
// shows it instead of offering the same bump again. A failed write is logged,
// never returned: the pull request already exists on GitHub.
func (s *Service) recordPullRequest(ctx context.Context, assetID int64, ecosystem, pkg, target, branch string, number int, url, manifest string) {
	if number <= 0 || url == "" {
		return
	}
	err := sqlcdb.New(s.db).UpsertFixPlanPullRequest(ctx, sqlcdb.UpsertFixPlanPullRequestParams{
		AssetID:   assetID,
		Ecosystem: ecosystem,
		Package:   pkg,
		Target:    target,
		Branch:    branch,
		Number:    int64(number),
		Url:       url,
		Manifest:  manifest,
		CreatedAt: s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		slog.Warn("could not record the fix plan pull request", "asset", assetID, "url", url, "error", err)
	}
}

// pullRequestPlan carries what the GitHub flow writes.
type pullRequestPlan struct {
	Ecosystem string
	Package   string
	Target    string
	Manifest  string
	Findings  []pullRequestStep
}

// openGitHubPullRequest performs the confirmed sequence: read the repository
// and its manifest, create the branch, commit the edit, open the pull request.
func (s *Service) openGitHubPullRequest(ctx context.Context, client PullRequestClient, owner, name string, plan pullRequestPlan) (PullRequestResult, error) {
	repo, err := client.Repo(ctx, owner, name)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}
	base := repo.DefaultBranch
	if base == "" {
		return PullRequestResult{}, fmt.Errorf("%w: GitHub reports no default branch for %s/%s", ErrPullRequestUnsupported, owner, name)
	}

	head, err := client.ResolveSHA(ctx, owner, name, base)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}

	branch := branchName(plan.Package, plan.Target)
	if _, exists, err := client.RefSHA(ctx, owner, name, branch); err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	} else if exists {
		return PullRequestResult{}, conflictWith(ctx, client, owner, name, branch)
	}

	file, err := client.File(ctx, owner, name, plan.Manifest, base)
	if err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}

	edited, err := editManifest(plan.Ecosystem, file.Content, plan.Package, plan.Target)
	if err != nil {
		return PullRequestResult{}, err
	}

	message := commitMessage(plan.Package, plan.Target)
	if err := client.CreateRef(ctx, owner, name, branch, head); err != nil {
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}
	// Once the branch exists a failure below would block the next attempt, so
	// it is removed again. Best effort: the original error stays the answer.
	undo := func(err error) (PullRequestResult, error) {
		if deleteErr := client.DeleteRef(ctx, owner, name, branch); deleteErr != nil {
			slog.Warn("could not delete the pull request branch after a failure",
				"branch", branch, "error", deleteErr)
		}
		return PullRequestResult{}, fmt.Errorf("%w: %w", connections.ErrUpstream, err)
	}
	if _, err := client.PutFile(ctx, github.PutFileInput{
		Owner:   owner,
		Name:    name,
		Path:    plan.Manifest,
		Branch:  branch,
		Message: message,
		Content: edited,
		SHA:     file.SHA,
	}); err != nil {
		return undo(err)
	}

	pr, err := client.CreatePullRequest(ctx, github.PullRequestInput{
		Owner: owner,
		Name:  name,
		Title: message,
		Head:  branch,
		Base:  base,
		Body:  pullRequestBody(plan),
	})
	if err != nil {
		return undo(err)
	}
	return PullRequestResult{URL: pr.HTMLURL, Number: pr.Number, Branch: branch, Manifest: plan.Manifest}, nil
}

// conflictWith builds the 409 error, naming the open pull request when the
// existing branch already has one.
func conflictWith(ctx context.Context, client PullRequestClient, owner, name, branch string) error {
	prs, err := client.PullRequestsForHead(ctx, owner, name, owner+":"+branch)
	if err != nil {
		// The branch conflict is still true when the lookup fails; the URL is
		// simply unknown.
		return &PullRequestConflict{Branch: branch}
	}
	conflict := &PullRequestConflict{Branch: branch}
	for _, pr := range prs {
		if pr.HTMLURL != "" {
			conflict.URL, conflict.Number = pr.HTMLURL, pr.Number
			break
		}
	}
	return conflict
}

// matchStep rebuilds the plan from the asset's findings and returns the step
// whose ecosystem, package and target all match the request.
func matchStep(rows []sqlcdb.ListLatestFindingsRow, ecosystem, pkg, target string) (fixplan.Step, bool) {
	inputs := make([]fixplan.Input, 0, len(rows))
	for _, row := range rows {
		inputs = append(inputs, fixplan.Input{
			ID:             row.ID,
			Ecosystem:      row.Ecosystem.String,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			Severity:       findings.Severity(row.Severity),
		})
	}
	plan := fixplan.Build(inputs)
	for _, step := range plan.Steps {
		if !strings.EqualFold(step.Ecosystem, ecosystem) {
			continue
		}
		if step.Package != pkg || step.TargetVersion != target {
			continue
		}
		return step, true
	}
	return fixplan.Step{}, false
}

// stepManifest maps the step's findings to the manifest it edits. The scanner
// reports the lockfile for most npm and Go packages, so the sibling manifest is
// what a bump rewrites. A step whose findings name no supported manifest is
// refused rather than guessed.
func stepManifest(ecosystem string, step fixplan.Step, rows []sqlcdb.ListLatestFindingsRow) (string, []pullRequestStep, error) {
	ids := make(map[int64]struct{}, len(step.FindingIDs))
	for _, id := range step.FindingIDs {
		ids[id] = struct{}{}
	}

	var (
		manifest string
		list     []pullRequestStep
	)
	for _, row := range rows {
		if _, ok := ids[row.ID]; !ok {
			continue
		}
		// The plan groups by package; a location from another package of the
		// same step (a shared lockfile) must not decide the manifest.
		if row.PackageName.String != step.Package {
			continue
		}
		list = append(list, pullRequestStep{
			RuleID:   row.RuleID.String,
			Severity: row.Severity,
		})
		if manifest == "" {
			if path, err := fixplan.ManifestPath(ecosystem, row.Location.String); err == nil {
				manifest = path
			}
		}
	}
	if manifest == "" {
		return "", nil, fmt.Errorf("%w: none of the step's findings names a %s manifest", ErrPullRequestUnsupported, ecosystem)
	}
	slices.SortFunc(list, func(a, b pullRequestStep) int {
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		return strings.Compare(a.Severity, b.Severity)
	})
	return manifest, list, nil
}

// editManifest applies the bump to the file the GitHub contents API returned.
func editManifest(ecosystem string, src []byte, pkg, target string) ([]byte, error) {
	var (
		edited []byte
		err    error
	)
	switch ecosystem {
	case "go":
		edited, err = fixplan.EditGoMod(src, pkg, target)
	case "npm":
		edited, err = fixplan.EditPackageJSON(src, pkg, target)
	default:
		return nil, fmt.Errorf("%w: ecosystem %q", ErrPullRequestUnsupported, ecosystem)
	}
	switch {
	case errors.Is(err, fixplan.ErrManifestNotFound):
		return nil, fmt.Errorf("%w: %s", ErrTransitiveDependency, pkg)
	case errors.Is(err, fixplan.ErrManifestUnsupported):
		return nil, fmt.Errorf("%w: %w", ErrPullRequestUnsupported, err)
	case err != nil:
		return nil, fmt.Errorf("reports: edit %s: %w", pkg, err)
	}
	return edited, nil
}

// splitRepo reads "owner/name" from a repository asset's ref.
func splitRepo(ref string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(ref, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("%w: asset ref %q is not owner/repo", ErrPullRequestUnsupported, ref)
	}
	return owner, name, nil
}

// branchName is the head branch a step creates: bastion/bump-<pkg>-<target>,
// with characters Git does not allow replaced. The result is deterministic, so
// a second attempt finds the first branch and reports the conflict.
func branchName(pkg, target string) string {
	return "bastion/bump-" + sanitizeRef(pkg, 60) + "-" + sanitizeRef(target, 60)
}

// sanitizeRef keeps the characters a Git ref allows and replaces the rest.
func sanitizeRef(value string, limit int) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= limit {
			break
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "dep"
	}
	return out
}

// commitMessage is the commit and pull request title for one step. Both values
// sit on one line: a newline would split the message and could smuggle text
// into a git trailer.
func commitMessage(pkg, target string) string {
	return "fix(deps): bump " + oneLine(pkg) + " to " + oneLine(target)
}

// oneLine flattens a value for a commit message or a list line.
func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// codeValue wraps a value in inline code for the pull request body. A backtick
// cannot be escaped inside inline code, so it is replaced rather than breaking
// the formatting.
func codeValue(value string) string {
	return "`" + strings.ReplaceAll(oneLine(value), "`", "'") + "`"
}

// pullRequestBody explains what the pull request closes and what it leaves for
// the user to do. The findings are a plain list of rule id and severity: no
// code, no scanner output.
func pullRequestBody(plan pullRequestPlan) string {
	var body strings.Builder
	fmt.Fprintf(&body, "Bumps %s to %s.\n\n", codeValue(plan.Package), codeValue(plan.Target))
	body.WriteString("Findings fixed:\n")
	for _, finding := range plan.Findings {
		rule := finding.RuleID
		if rule == "" {
			rule = "unnamed finding"
		}
		fmt.Fprintf(&body, "- %s (%s)\n", codeValue(rule), oneLine(finding.Severity))
	}
	body.WriteString("\nOnly the manifest was changed. Regenerate the lockfile (go mod tidy / npm install) before merging.\n\n")
	body.WriteString("Opened by bastion after you confirmed it.\n")
	return body.String()
}
